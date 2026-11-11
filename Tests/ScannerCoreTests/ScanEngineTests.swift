import XCTest
@testable import ScannerCore

/// Records every probe the engine makes, and how many run at once.
actor ProbeLog {
    private(set) var calls: [String] = []
    private var inFlight = 0
    private(set) var maxInFlight = 0

    /// Returns which attempt this is for the address and port (1 for the first).
    func begin(_ key: String) -> Int {
        calls.append(key)
        inFlight += 1
        maxInFlight = max(maxInFlight, inFlight)
        return calls.filter { $0 == key }.count
    }

    func end() {
        inFlight -= 1
    }

    func attempts(_ key: String) -> Int {
        calls.filter { $0 == key }.count
    }
}

/// Fake network: `answer` decides each probe's result from address, port and attempt number.
private func fakeDependencies(
    log: ProbeLog,
    delayNanoseconds: UInt64 = 0,
    names: [String: String] = [:],
    answer: @escaping @Sendable (_ address: String, _ port: UInt16, _ attempt: Int) -> ProbeResult
) -> ScanDependencies {
    ScanDependencies(
        probe: { address, port, _ in
            let attempt = await log.begin("\(address):\(port)")
            if delayNanoseconds > 0 {
                do {
                    try await Task.sleep(nanoseconds: delayNanoseconds)
                } catch {
                    await log.end()
                    return .filtered
                }
            }
            await log.end()
            return answer(address, port, attempt)
        },
        resolve: { name in
            names[name]
        }
    )
}

private func collect(_ request: ScanRequest, _ deps: ScanDependencies) async -> [ScanEvent] {
    var events: [ScanEvent] = []
    for await event in ScanEngine.run(request, using: deps) {
        events.append(event)
    }
    return events
}

private extension Array where Element == ScanEvent {
    var portEvents: [(host: Int, port: UInt16, state: PortState)] {
        compactMap { event -> (host: Int, port: UInt16, state: PortState)? in
            if case let .port(hostID, port, state) = event {
                return (hostID, port, state)
            }
            return nil
        }
    }

    var startedHosts: [(label: String, address: String)] {
        compactMap { event -> (label: String, address: String)? in
            if case let .hostStarted(_, label, address) = event {
                return (label, address)
            }
            return nil
        }
    }

    var finishedHosts: [(closed: Int, filtered: Int)] {
        compactMap { event -> (closed: Int, filtered: Int)? in
            if case let .hostFinished(_, closed, filtered) = event {
                return (closed, filtered)
            }
            return nil
        }
    }

    var discovery: (up: Int, total: Int)? {
        for event in self {
            if case let .discovered(up, total) = event {
                return (up, total)
            }
        }
        return nil
    }

    var unresolvedNames: [String] {
        compactMap { event -> String? in
            if case let .unresolved(name) = event {
                return name
            }
            return nil
        }
    }

    var permissionDeniedCount: Int {
        filter { event in
            if case .permissionDenied = event {
                return true
            }
            return false
        }.count
    }

    var lastProgress: Double? {
        compactMap { event -> Double? in
            if case let .progress(value) = event {
                return value
            }
            return nil
        }.last
    }
}

final class ScanEngineTests: XCTestCase {
    func testShortPortListReportsEveryPort() async {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log) { _, port, _ in
            switch port {
            case 22: return .open
            case 80: return .closed
            default: return .filtered
            }
        }
        let request = ScanRequest(targets: [.address("10.0.0.5")], ports: [22, 80, 443], timing: .normal, skipDiscovery: false)

        let events = await collect(request, deps)

        XCTAssertEqual(events.startedHosts.map(\.address), ["10.0.0.5"])
        var states: [UInt16: PortState] = [:]
        for event in events.portEvents {
            states[event.port] = event.state
        }
        XCTAssertEqual(states, [22: .open, 80: .closed, 443: .filtered])
        XCTAssertEqual(events.portEvents.count, 3)
        XCTAssertEqual(events.finishedHosts.first?.closed, 1)
        XCTAssertEqual(events.finishedHosts.first?.filtered, 1)
        XCTAssertEqual(events.lastProgress, 1.0)

        // Normal timing retries a silent port once; answered ports are not retried.
        let filteredAttempts = await log.attempts("10.0.0.5:443")
        let openAttempts = await log.attempts("10.0.0.5:22")
        XCTAssertEqual(filteredAttempts, 2)
        XCTAssertEqual(openAttempts, 1)
    }

    func testLongPortListReportsOnlyOpenPortsAndKeepsConcurrencyBounded() async {
        let log = ProbeLog()
        let openPorts: Set<UInt16> = [22, 80, 443]
        let deps = fakeDependencies(log: log, delayNanoseconds: 1_000_000) { _, port, _ in
            if openPorts.contains(port) { return .open }
            return port % 2 == 0 ? .closed : .filtered
        }
        let ports = TopPorts.top1000
        let timing = TimingTemplate.insane
        let request = ScanRequest(targets: [.address("10.0.0.7")], ports: ports, timing: timing, skipDiscovery: false)

        let events = await collect(request, deps)

        XCTAssertEqual(Set(events.portEvents.map(\.port)), openPorts)
        XCTAssertTrue(events.portEvents.allSatisfy { $0.state == .open })

        let others = ports.filter { !openPorts.contains($0) }
        let expectedClosed = others.filter { $0 % 2 == 0 }.count
        XCTAssertEqual(events.finishedHosts.first?.closed, expectedClosed)
        XCTAssertEqual(events.finishedHosts.first?.filtered, others.count - expectedClosed)
        XCTAssertEqual(events.lastProgress, 1.0)

        let calls = await log.calls.count
        let peak = await log.maxInFlight
        XCTAssertEqual(calls, ports.count, "insane timing does not retry")
        XCTAssertLessThanOrEqual(peak, timing.concurrency)
        XCTAssertGreaterThan(peak, ScanEngine.initialWindow, "probes should run in parallel")
    }

    func testWindowStartsSmallThenWidens() async throws {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log, delayNanoseconds: 300_000_000) { _, _, _ in .closed }
        let request = ScanRequest(targets: [.address("10.0.0.6")], ports: Array(1...200), timing: .insane, skipDiscovery: false)

        let scan = Task { await collect(request, deps) }
        try await Task.sleep(nanoseconds: 100_000_000)
        let firstWave = await log.calls.count
        XCTAssertEqual(firstWave, ScanEngine.initialWindow, "only the first window is sent before any answer")

        let events = await scan.value
        let peak = await log.maxInFlight
        XCTAssertEqual(events.finishedHosts.first?.closed, 200)
        XCTAssertGreaterThan(peak, ScanEngine.initialWindow, "the window grows as answers arrive")
        XCTAssertLessThanOrEqual(peak, TimingTemplate.insane.concurrency)
    }

    func testAggressiveTimingRetriesOnce() async {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log) { _, _, attempt in
            attempt == 1 ? .filtered : .open
        }
        let request = ScanRequest(targets: [.address("10.0.0.10")], ports: [443], timing: .aggressive, skipDiscovery: false)

        let events = await collect(request, deps)

        XCTAssertEqual(events.portEvents.first?.state, .open)
        let attempts = await log.attempts("10.0.0.10:443")
        XCTAssertEqual(attempts, 2)
    }

    func testDiscoveryScansOnlyHostsThatAnswer() async {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log) { address, port, _ in
            switch address {
            case "10.0.0.1": return port == 22 ? .open : .closed
            case "10.0.0.3": return .denied
            default: return .filtered
            }
        }
        let request = ScanRequest(
            targets: [.address("10.0.0.1"), .address("10.0.0.2"), .address("10.0.0.3")],
            ports: [22],
            timing: .insane,
            skipDiscovery: false
        )

        let events = await collect(request, deps)

        XCTAssertEqual(events.discovery?.up, 1)
        XCTAssertEqual(events.discovery?.total, 3)
        XCTAssertEqual(events.startedHosts.map(\.address), ["10.0.0.1"])
        XCTAssertEqual(events.portEvents.map(\.port), [22])
        XCTAssertEqual(events.portEvents.first?.state, .open)
        XCTAssertEqual(events.permissionDeniedCount, 1)
    }

    func testSkipDiscoveryScansEveryAddress() async {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log) { address, _, _ in
            address == "10.0.0.3" ? .denied : .filtered
        }
        let request = ScanRequest(
            targets: [.address("10.0.0.1"), .address("10.0.0.2"), .address("10.0.0.3")],
            ports: [22, 80],
            timing: .insane,
            skipDiscovery: true
        )

        let events = await collect(request, deps)

        XCTAssertNil(events.discovery)
        XCTAssertEqual(events.startedHosts.map(\.address), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        XCTAssertEqual(events.finishedHosts.count, 3)
        XCTAssertEqual(events.permissionDeniedCount, 1)
        let calls = await log.calls.count
        XCTAssertEqual(calls, 6, "no discovery probes when it is skipped")
    }

    func testHostnamesAreResolvedAndDuplicatesDropped() async {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log, names: ["router.lan": "10.0.0.1"]) { _, _, _ in .open }
        let request = ScanRequest(
            targets: [.hostname("router.lan"), .hostname("missing.lan"), .address("10.0.0.1")],
            ports: [80],
            timing: .insane,
            skipDiscovery: false
        )

        let events = await collect(request, deps)

        XCTAssertEqual(events.unresolvedNames, ["missing.lan"])
        XCTAssertEqual(events.startedHosts.count, 1)
        XCTAssertEqual(events.startedHosts.first?.label, "router.lan")
        XCTAssertEqual(events.startedHosts.first?.address, "10.0.0.1")
        XCTAssertNil(events.discovery, "a single host is scanned without discovery")
    }

    func testRetryCatchesALateAnswer() async {
        let answer: @Sendable (String, UInt16, Int) -> ProbeResult = { _, _, attempt in
            attempt == 1 ? .filtered : .open
        }
        let target: [ScanTarget] = [.address("10.0.0.9")]

        let normal = await collect(
            ScanRequest(targets: target, ports: [8080], timing: .normal, skipDiscovery: false),
            fakeDependencies(log: ProbeLog(), answer: answer)
        )
        XCTAssertEqual(normal.portEvents.first?.state, .open)

        let insane = await collect(
            ScanRequest(targets: target, ports: [8080], timing: .insane, skipDiscovery: false),
            fakeDependencies(log: ProbeLog(), answer: answer)
        )
        XCTAssertEqual(insane.portEvents.first?.state, .filtered, "insane timing does not retry")
    }

    func testPermissionDeniedIsReportedOnce() async {
        let deps = fakeDependencies(log: ProbeLog()) { _, _, _ in .denied }
        let request = ScanRequest(targets: [.address("10.0.0.4")], ports: Array(1...50), timing: .insane, skipDiscovery: false)

        let events = await collect(request, deps)

        XCTAssertEqual(events.permissionDeniedCount, 1)
        XCTAssertEqual(events.finishedHosts.first?.filtered, 50)
    }

    func testStoppingTheConsumerStopsTheScan() async throws {
        let log = ProbeLog()
        let deps = fakeDependencies(log: log, delayNanoseconds: 20_000_000) { _, _, _ in .closed }
        let request = ScanRequest(
            targets: [.address("10.0.0.8")],
            ports: Array(1...2000),
            timing: .normal,
            skipDiscovery: false
        )

        let consumer = Task {
            var count = 0
            for await _ in ScanEngine.run(request, using: deps) {
                count += 1
            }
            return count
        }
        try await Task.sleep(nanoseconds: 60_000_000)
        consumer.cancel()
        _ = await consumer.value

        let callsAtStop = await log.calls.count
        try await Task.sleep(nanoseconds: 200_000_000)
        let callsLater = await log.calls.count

        XCTAssertLessThan(callsLater, 1000, "the scan should stop well before all 2000 ports")
        XCTAssertLessThanOrEqual(callsLater - callsAtStop, TimingTemplate.normal.concurrency, "no new batch starts after stopping")
    }
}
