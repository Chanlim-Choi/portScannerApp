import Foundation

struct ScanRequest: Sendable {
    let targets: [ScanTarget]
    let ports: [UInt16]
    let timing: TimingTemplate
    /// Scan every address without checking first whether it is up (nmap -Pn).
    let skipDiscovery: Bool
}

/// What the engine needs from the outside world. The app passes `.live`
/// (real sockets and DNS); tests pass fakes so the engine can be checked
/// without a network or an iPhone.
struct ScanDependencies: Sendable {
    /// One TCP connect attempt: address, port, timeout in seconds.
    var probe: @Sendable (String, UInt16, TimeInterval) async -> ProbeResult
    /// Turns a hostname into one numeric address, or nil when it does not resolve.
    var resolve: @Sendable (String) async -> String?
}

enum ScanEvent: Sendable {
    case status(String)
    case unresolved(String)
    case discovered(up: Int, total: Int)
    case hostStarted(id: Int, label: String, address: String)
    case port(hostID: Int, port: UInt16, state: PortState)
    case hostFinished(id: Int, closed: Int, filtered: Int)
    case progress(Double)
    case permissionDenied
}

/// Runs a scan off the main thread and reports what it finds as a stream of
/// events. Dropping or cancelling the stream stops the scan.
enum ScanEngine {
    private struct Host: Sendable {
        let label: String
        let address: String
    }

    private enum Liveness: Sendable {
        case up
        case down
        case denied
    }

    /// An answer on any of these, open or refused, proves the host is up. This
    /// is how nmap finds hosts when it runs without raw-socket privileges.
    private static let discoveryPorts: [UInt16] = [80, 443, 22, 445, 62078]
    private static let discoveryConcurrency = 32

    /// Connections opened at once when a host's scan starts; the window then
    /// grows by one with every answer, up to the timing template's limit.
    /// Starting small matters on a LAN: until the phone knows the target's
    /// hardware (ARP) address, iOS queues only a few packets for it and drops
    /// the rest, which would make open ports look filtered.
    static let initialWindow = 8

    /// Share of the progress bar used by host discovery, when it runs.
    private static let discoveryShare = 0.2

    static func run(_ request: ScanRequest, using deps: ScanDependencies) -> AsyncStream<ScanEvent> {
        AsyncStream(ScanEvent.self) { continuation in
            let task = Task.detached(priority: .userInitiated) {
                await ScanEngine.execute(request, deps, continuation)
                continuation.finish()
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    private static func execute(
        _ request: ScanRequest,
        _ deps: ScanDependencies,
        _ out: AsyncStream<ScanEvent>.Continuation
    ) async {
        var hosts = await resolve(request.targets, deps, out)
        guard !hosts.isEmpty, !Task.isCancelled else { return }

        var progressBase = 0.0
        if hosts.count > 1 && !request.skipDiscovery {
            let candidates = hosts.count
            out.yield(.status("Looking for live hosts among \(candidates) addresses…"))
            hosts = await discover(hosts, request.timing, deps, out)
            guard !Task.isCancelled else { return }
            out.yield(.discovered(up: hosts.count, total: candidates))
            guard !hosts.isEmpty else { return }
            progressBase = discoveryShare
        }

        let ports = request.ports
        let timing = request.timing
        // With a short port list, show every port; otherwise only the open ones.
        let reportEveryPort = ports.count <= 64
        let total = hosts.count * ports.count
        let step = max(1, total / 200)
        var done = 0
        var deniedReported = false
        out.yield(.progress(progressBase))

        for (index, host) in hosts.enumerated() {
            if Task.isCancelled { return }
            out.yield(.hostStarted(id: index, label: host.label, address: host.address))
            out.yield(.status("Scanning \(host.label) (\(index + 1) of \(hosts.count))…"))
            let address = host.address

            let counts = await withTaskGroup(of: (UInt16, ProbeResult).self, returning: (Int, Int).self) { group in
                var next = 0
                var inFlight = 0
                var window = min(ScanEngine.initialWindow, timing.concurrency)
                var closed = 0
                var filtered = 0

                while next < ports.count && inFlight < window {
                    let port = ports[next]
                    next += 1
                    inFlight += 1
                    group.addTask {
                        (port, await ScanEngine.probe(address, port, timing, deps))
                    }
                }

                while let item = await group.next() {
                    inFlight -= 1
                    // After Stop, results only reflect the cancellation; drop them.
                    if Task.isCancelled { continue }
                    let (port, result) = item
                    done += 1

                    let state: PortState
                    switch result {
                    case .open:
                        state = .open
                    case .closed:
                        state = .closed
                        closed += 1
                    case .filtered:
                        state = .filtered
                        filtered += 1
                    case .denied:
                        state = .filtered
                        filtered += 1
                        if !deniedReported {
                            deniedReported = true
                            out.yield(.permissionDenied)
                        }
                    }

                    if state == .open || reportEveryPort {
                        out.yield(.port(hostID: index, port: port, state: state))
                    }
                    if done == total {
                        out.yield(.progress(1))
                    } else if done % step == 0 {
                        out.yield(.progress(progressBase + (1 - progressBase) * Double(done) / Double(total)))
                    }

                    // Widen the window by one per answer, then refill it.
                    window = min(window + 1, timing.concurrency)
                    while next < ports.count && inFlight < window {
                        let upcoming = ports[next]
                        next += 1
                        inFlight += 1
                        group.addTask {
                            (upcoming, await ScanEngine.probe(address, upcoming, timing, deps))
                        }
                    }
                }
                return (closed, filtered)
            }

            if Task.isCancelled { return }
            out.yield(.hostFinished(id: index, closed: counts.0, filtered: counts.1))
        }
    }

    private static func resolve(
        _ targets: [ScanTarget],
        _ deps: ScanDependencies,
        _ out: AsyncStream<ScanEvent>.Continuation
    ) async -> [Host] {
        var hosts: [Host] = []
        var seen = Set<String>()
        for target in targets {
            if Task.isCancelled { break }
            switch target {
            case .address(let address):
                if seen.insert(address).inserted {
                    hosts.append(Host(label: address, address: address))
                }
            case .hostname(let name):
                out.yield(.status("Resolving \(name)…"))
                if let address = await deps.resolve(name) {
                    if seen.insert(address).inserted {
                        hosts.append(Host(label: name, address: address))
                    }
                } else {
                    out.yield(.unresolved(name))
                }
            }
        }
        return hosts
    }

    /// Returns the hosts that answered on at least one discovery port.
    private static func discover(
        _ hosts: [Host],
        _ timing: TimingTemplate,
        _ deps: ScanDependencies,
        _ out: AsyncStream<ScanEvent>.Continuation
    ) async -> [Host] {
        let timeout = max(timing.timeout, 1.0)
        var states = [Liveness](repeating: .down, count: hosts.count)

        await withTaskGroup(of: (Int, Liveness).self) { group in
            var next = 0
            var done = 0

            while next < hosts.count && next < ScanEngine.discoveryConcurrency {
                let index = next
                let address = hosts[index].address
                next += 1
                group.addTask {
                    (index, await ScanEngine.liveness(of: address, timeout: timeout, deps))
                }
            }

            while let item = await group.next() {
                if Task.isCancelled { continue }
                let (index, result) = item
                states[index] = result
                done += 1
                out.yield(.progress(ScanEngine.discoveryShare * Double(done) / Double(hosts.count)))

                if !Task.isCancelled && next < hosts.count {
                    let upcoming = next
                    let address = hosts[upcoming].address
                    next += 1
                    group.addTask {
                        (upcoming, await ScanEngine.liveness(of: address, timeout: timeout, deps))
                    }
                }
            }
        }

        if states.contains(.denied) {
            out.yield(.permissionDenied)
        }
        var live: [Host] = []
        for (index, host) in hosts.enumerated() where states[index] == .up {
            live.append(host)
        }
        return live
    }

    private static func liveness(
        of address: String,
        timeout: TimeInterval,
        _ deps: ScanDependencies
    ) async -> Liveness {
        await withTaskGroup(of: ProbeResult.self, returning: Liveness.self) { group in
            for port in ScanEngine.discoveryPorts {
                group.addTask {
                    await deps.probe(address, port, timeout)
                }
            }

            var denied = false
            while let result = await group.next() {
                switch result {
                case .open, .closed:
                    // One answer is enough; drop the other probes.
                    group.cancelAll()
                    return Liveness.up
                case .denied:
                    denied = true
                case .filtered:
                    break
                }
            }
            return denied ? Liveness.denied : Liveness.down
        }
    }

    private static func probe(
        _ address: String,
        _ port: UInt16,
        _ timing: TimingTemplate,
        _ deps: ScanDependencies
    ) async -> ProbeResult {
        var result = await deps.probe(address, port, timing.timeout)
        var attemptsLeft = timing.retries
        while result == .filtered && attemptsLeft > 0 && !Task.isCancelled {
            attemptsLeft -= 1
            result = await deps.probe(address, port, timing.timeout)
        }
        return result
    }
}
