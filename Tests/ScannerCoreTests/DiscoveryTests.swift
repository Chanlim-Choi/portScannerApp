import XCTest
@testable import ScannerCore

/// A fake network for the discovery engine.
private func discoveryDependencies(
    log: ProbeLog,
    pingReplies: [String: TimeInterval]?,
    tcp: @escaping @Sendable (String, UInt16) -> ProbeResult,
    names: [String: String] = [:],
    services: [BonjourService] = []
) -> ScanDependencies {
    ScanDependencies(
        probe: { address, port, _ in
            _ = await log.begin("\(address):\(port)")
            await log.end()
            return tcp(address, port)
        },
        resolve: { _ in nil },
        ping: { addresses, _ in
            pingReplies.map { replies in
                replies.filter { addresses.contains($0.key) }
            }
        },
        reverseName: { address in
            names[address]
        },
        browse: { _ in
            AsyncStream { continuation in
                for service in services {
                    continuation.yield(service)
                }
                continuation.finish()
            }
        }
    )
}

private struct DiscoveryResult {
    var devices: [String: Device] = [:]
    var events: [DiscoveryEvent] = []

    var lastProgress: Double? {
        events.compactMap { event -> Double? in
            if case let .progress(value) = event {
                return value
            }
            return nil
        }.last
    }

    func count(where match: (DiscoveryEvent) -> Bool) -> Int {
        events.filter(match).count
    }
}

private func discover(_ request: DiscoveryRequest, _ deps: ScanDependencies) async -> DiscoveryResult {
    var result = DiscoveryResult()
    for await event in DiscoveryEngine.run(request, using: deps) {
        result.events.append(event)
        if case let .device(device) = event {
            result.devices[device.address] = device
        }
    }
    return result
}

final class DiscoveryEngineTests: XCTestCase {
    private let subnet = (1...10).map { "10.0.0.\($0)" }

    func testFindsDevicesByPingTcpAndBonjour() async {
        let log = ProbeLog()
        let deps = discoveryDependencies(
            log: log,
            pingReplies: ["10.0.0.1": 0.002, "10.0.0.3": 0.0001],
            tcp: { address, port in
                address == "10.0.0.5" && port == 62078 ? .closed : .filtered
            },
            names: ["10.0.0.1": "router.lan.", "10.0.0.7": "kitchen.local"],
            services: [
                BonjourService(name: "A1B2C3D4E5F6@Kitchen", type: "_raop._tcp", address: "10.0.0.7", port: 7000, model: "AudioAccessory5,1"),
                BonjourService(name: "Router admin", type: "_http._tcp", address: "10.0.0.1", port: 80),
            ]
        )
        let request = DiscoveryRequest(addresses: subnet, ownAddress: "10.0.0.3")

        let result = await discover(request, deps)

        XCTAssertEqual(Set(result.devices.keys), ["10.0.0.1", "10.0.0.3", "10.0.0.5", "10.0.0.7"])

        let router = result.devices["10.0.0.1"]
        XCTAssertEqual(router?.methods, [.ping, .bonjour])
        XCTAssertEqual(router?.hostName, "router.lan", "the trailing dot is removed")
        XCTAssertEqual(router?.latency, 0.002)
        XCTAssertEqual(router?.title, "Router admin", "a Bonjour name beats the host name")

        let phone = result.devices["10.0.0.3"]
        XCTAssertEqual(phone?.isThisDevice, true)
        XCTAssertEqual(phone?.title, "This iPhone")

        let quiet = result.devices["10.0.0.5"]
        XCTAssertEqual(quiet?.methods, [.tcp])
        XCTAssertNotNil(quiet?.latency)
        XCTAssertEqual(quiet?.title, "Unknown device")

        let speaker = result.devices["10.0.0.7"]
        XCTAssertTrue(speaker?.methods.contains(.bonjour) ?? false)
        XCTAssertEqual(speaker?.title, "Kitchen", "the hardware address prefix is removed")
        XCTAssertEqual(speaker?.model, "AudioAccessory5,1")
        XCTAssertEqual(speaker?.hostName, "kitchen.local")

        // Addresses that answered ping are not probed over TCP.
        let routerProbes = await log.calls.filter { $0.hasPrefix("10.0.0.1:") }
        XCTAssertTrue(routerProbes.isEmpty)
        XCTAssertEqual(result.lastProgress, 1)
        XCTAssertEqual(result.count { if case .pingUnavailable = $0 { return true }; return false }, 0)
    }

    func testWithoutPingTcpStillFindsDevices() async {
        let deps = discoveryDependencies(
            log: ProbeLog(),
            pingReplies: nil,
            tcp: { address, port in
                address == "10.0.0.4" && port == 443 ? .open : .filtered
            }
        )

        let result = await discover(DiscoveryRequest(addresses: subnet, ownAddress: nil), deps)

        XCTAssertEqual(Set(result.devices.keys), ["10.0.0.4"])
        XCTAssertEqual(result.devices["10.0.0.4"]?.methods, [.tcp])
        XCTAssertEqual(result.count { if case .pingUnavailable = $0 { return true }; return false }, 1)
    }

    func testLocalNetworkDenialIsReportedOnce() async {
        let deps = discoveryDependencies(log: ProbeLog(), pingReplies: [:], tcp: { _, _ in .denied })

        let result = await discover(DiscoveryRequest(addresses: subnet, ownAddress: nil), deps)

        XCTAssertTrue(result.devices.isEmpty)
        XCTAssertEqual(result.count { if case .permissionDenied = $0 { return true }; return false }, 1)
    }

    func testStoppingEndsTheSearch() async throws {
        let deps = ScanDependencies(
            probe: { _, _, _ in
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                return .filtered
            },
            resolve: { _ in nil },
            ping: { _, _ in [:] },
            reverseName: { _ in nil },
            browse: { _ in AsyncStream { $0.finish() } }
        )
        let request = DiscoveryRequest(addresses: (1...254).map { "10.1.1.\($0)" }, ownAddress: nil)
        let started = Date()

        let consumer = Task {
            var count = 0
            for await _ in DiscoveryEngine.run(request, using: deps) {
                count += 1
            }
            return count
        }
        try await Task.sleep(nanoseconds: 200_000_000)
        consumer.cancel()
        _ = await consumer.value

        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "a full sweep would take far longer")
    }
}

final class DeviceNamingTests: XCTestCase {
    func testServiceNamesAreCleaned() {
        XCTAssertEqual(BonjourCatalog.displayName(instance: "AABBCCDDEEFF@Living Room", type: "_raop._tcp"), "Living Room")
        XCTAssertEqual(BonjourCatalog.displayName(instance: "nas [00:11:22:33:44:55]", type: "_workstation._tcp"), "nas")
        XCTAssertEqual(BonjourCatalog.displayName(instance: "Office Printer", type: "_ipp._tcp"), "Office Printer")
    }

    func testFriendlyNameWins() {
        let cast = BonjourService(name: "Google-Home-Mini-1a2b3c", type: "_googlecast._tcp", address: "10.0.0.9", port: 8009, friendlyName: "Bedroom speaker", model: "Google Home Mini")
        XCTAssertEqual(cast.displayName, "Bedroom speaker")
        XCTAssertEqual(cast.detail, "Bedroom speaker · port 8009")
        XCTAssertEqual(cast.title, "Google Cast")
    }

    func testBestServiceNamesTheDevice() {
        var device = Device(address: "10.0.0.2", hostName: "macbook.local")
        XCTAssertEqual(device.title, "macbook.local")

        device.services = [
            BonjourService(name: "Web admin", type: "_http._tcp", address: "10.0.0.2", port: 80),
            BonjourService(name: "Chan's MacBook Pro", type: "_companion-link._tcp", address: "10.0.0.2", port: 49152),
        ]
        XCTAssertEqual(device.title, "Chan's MacBook Pro", "an Apple device name beats a web page name")
    }

    func testSubtitleAndMethods() {
        var device = Device(address: "192.168.1.20")
        device.latency = 0.0004
        device.methods = [.bonjour, .ping]
        XCTAssertEqual(device.subtitle, "192.168.1.20 · <1 ms")
        XCTAssertEqual(device.methodsText, "Ping, Bonjour")

        device.latency = 0.0123
        XCTAssertEqual(device.subtitle, "192.168.1.20 · 12 ms")
    }

    func testDevicesSortNumerically() {
        let addresses = ["10.0.0.10", "10.0.0.9", "10.0.0.100", "10.0.0.2"]
        let sorted = addresses.map { Device(address: $0) }.sorted { $0.sortKey < $1.sortKey }.map(\.address)
        XCTAssertEqual(sorted, ["10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.0.100"])
    }
}

final class BonjourCatalogTests: XCTestCase {
    func testInfoPlistListsExactlyTheBrowsedTypes() throws {
        // iOS refuses to browse a type that is not listed under NSBonjourServices.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("PortScanner-Info.plist"))
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        let listed = try XCTUnwrap(plist["NSBonjourServices"] as? [String])

        let catalog = BonjourCatalog.types.map { $0.type }
        XCTAssertEqual(Set(listed), Set(catalog))
        XCTAssertEqual(listed.count, Set(listed).count, "no duplicates in the plist")
        XCTAssertEqual(catalog.count, Set(catalog).count, "no duplicates in the catalog")
        for type in catalog {
            XCTAssertTrue(type.hasPrefix("_") && (type.hasSuffix("._tcp") || type.hasSuffix("._udp")), "\(type) is not a service type")
        }
    }
}
