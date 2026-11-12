import Foundation

/// How a device was found.
enum DiscoveryMethod: String, CaseIterable, Hashable, Sendable {
    /// Answered an ICMP echo (ping).
    case ping
    /// Accepted or refused a TCP connection.
    case tcp
    /// Announced a service over Bonjour.
    case bonjour

    var title: String {
        switch self {
        case .ping: return "Ping"
        case .tcp: return "TCP"
        case .bonjour: return "Bonjour"
        }
    }
}

/// A Bonjour service, resolved to the IPv4 address that offers it.
struct BonjourService: Hashable, Sendable {
    /// The instance name, for example "Living Room".
    let name: String
    /// The service type, for example "_airplay._tcp".
    let type: String
    let address: String
    let port: UInt16?
    /// The "fn" TXT entry some devices (Google Cast) use for their real name.
    var friendlyName: String?
    /// A model string from the TXT record, when the service gives one.
    var model: String?

    var title: String { BonjourCatalog.title(for: type) }

    var displayName: String {
        friendlyName ?? BonjourCatalog.displayName(instance: name, type: type)
    }

    /// A Google Cast speaker group, announced by one of its member speakers.
    var isGroup: Bool {
        model == "Google Cast Group"
    }

    /// The name is a machine ID ("Google-Home-Mini-3f2a…", a hex string)
    /// rather than one a person chose.
    var hasMachineName: Bool {
        friendlyName == nil && BonjourCatalog.looksLikeMachineID(displayName)
    }

    /// How good this service is as the source of its device's name and
    /// model; lower is better.
    var nameRank: Int {
        if isGroup { return 9 }
        if hasMachineName { return 8 }
        return BonjourCatalog.nameRank(for: type)
    }

    /// The same service at another address (used for the phone's own
    /// services, which resolve to loopback).
    func moved(to newAddress: String) -> BonjourService {
        BonjourService(name: name, type: type, address: newAddress, port: port, friendlyName: friendlyName, model: model)
    }

    var detail: String {
        if let port = port {
            return "\(displayName) · port \(port)"
        }
        return displayName
    }
}

struct Device: Identifiable, Hashable, Sendable {
    let address: String
    /// Reverse-DNS name, for example "nas.local".
    var hostName: String?
    var services: [BonjourService] = []
    /// Fastest response seen, in seconds.
    var latency: TimeInterval?
    var methods: Set<DiscoveryMethod> = []
    /// The phone running the app.
    var isThisDevice = false

    var id: String { address }

    /// Services from the best name source to the worst, keeping arrival order
    /// among equals.
    private var rankedServices: [BonjourService] {
        services.enumerated().sorted { first, second in
            let firstRank = first.element.nameRank
            let secondRank = second.element.nameRank
            return firstRank != secondRank ? firstRank < secondRank : first.offset < second.offset
        }.map { $0.element }
    }

    /// The best name known: a Bonjour name a person chose, then the
    /// reverse-DNS name, then a Bonjour machine ID.
    var name: String? {
        guard let best = rankedServices.first(where: { !$0.isGroup }) else {
            return hostName ?? services.first?.displayName
        }
        if best.hasMachineName, let hostName = hostName {
            return hostName
        }
        return best.displayName
    }

    var title: String {
        isThisDevice ? "This device" : (name ?? "Unknown device")
    }

    /// The raw model string from the best service that has one, for
    /// example "Mac14,2" or "Google Home Mini".
    var model: String? {
        rankedServices.filter { !$0.isGroup }.lazy.compactMap { $0.model }.first
    }

    /// The model for people: "MacBook Air" rather than "Mac14,2".
    var modelDescription: String? {
        guard let model = model else { return nil }
        return AppleModel.family(model) ?? model
    }

    var subtitle: String {
        var parts = [address]
        if let model = modelDescription {
            parts.append(model)
        }
        if let latency = latency {
            parts.append(Device.format(latency: latency))
        }
        return parts.joined(separator: " · ")
    }

    var methodsText: String {
        DiscoveryMethod.allCases.filter { methods.contains($0) }.map { $0.title }.joined(separator: ", ")
    }

    /// Numeric order of the IPv4 address, for sorting.
    var sortKey: UInt32 {
        TargetParser.ipv4Value(address) ?? .max
    }

    static func format(latency: TimeInterval) -> String {
        let milliseconds = latency * 1000
        return milliseconds < 1 ? "<1 ms" : String(format: "%.0f ms", milliseconds)
    }
}

struct DiscoveryRequest: Sendable {
    /// Addresses to sweep, usually the phone's subnet.
    let addresses: [String]
    /// The phone's own address, so it can be labelled.
    let ownAddress: String?
    var pingTimeout: TimeInterval = 1.0
    var tcpTimeout: TimeInterval = 1.0
    /// How long to listen for Bonjour announcements.
    var browseDuration: TimeInterval = 6
}

enum DiscoveryEvent: Sendable {
    case status(String)
    case progress(Double)
    /// A device was found or learned something new; the full current record.
    case device(Device)
    /// No ICMP socket could be opened, so ping was skipped.
    case pingUnavailable
    /// iOS blocked a connection because Local Network access is off.
    case permissionDenied
}

/// Finds the devices on a network: an ICMP sweep, then TCP for the addresses
/// that ignore ping, with Bonjour listening the whole time, then reverse-DNS
/// names. Like nmap -sn, but without ARP, which iOS does not allow.
enum DiscoveryEngine {
    static let hostConcurrency = 64
    static let nameConcurrency = 16

    static func run(_ request: DiscoveryRequest, using deps: ScanDependencies) -> AsyncStream<DiscoveryEvent> {
        AsyncStream(DiscoveryEvent.self) { continuation in
            let task = Task.detached(priority: .userInitiated) {
                await DiscoveryEngine.execute(request, deps, continuation)
                continuation.finish()
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    private static func execute(
        _ request: DiscoveryRequest,
        _ deps: ScanDependencies,
        _ out: AsyncStream<DiscoveryEvent>.Continuation
    ) async {
        let table = DeviceTable(ownAddress: request.ownAddress, out: out)
        out.yield(.progress(0))

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                for await service in deps.browse(request.browseDuration) {
                    await table.add(service)
                }
            }
            group.addTask {
                await DiscoveryEngine.sweep(request, deps, table, out)
            }
            await group.waitForAll()
        }
        if Task.isCancelled { return }

        await lookUpNames(deps, table, out)
        if Task.isCancelled { return }
        out.yield(.progress(1))
    }

    private static func sweep(
        _ request: DiscoveryRequest,
        _ deps: ScanDependencies,
        _ table: DeviceTable,
        _ out: AsyncStream<DiscoveryEvent>.Continuation
    ) async {
        let addresses = request.addresses
        guard !addresses.isEmpty else { return }

        out.yield(.status("Pinging \(addresses.count) addresses…"))
        if let replies = await deps.ping(addresses, request.pingTimeout) {
            for address in addresses {
                if let latency = replies[address] {
                    await table.found(address, by: .ping, latency: latency)
                }
            }
        } else {
            out.yield(.pingUnavailable)
        }
        if Task.isCancelled { return }
        out.yield(.progress(0.2))

        // Many phones and firewalled computers ignore ping but still answer
        // (or refuse) a TCP connection.
        let known = await table.knownAddresses()
        let pending = addresses.filter { !known.contains($0) }
        if !pending.isEmpty {
            out.yield(.status("Checking \(pending.count) quiet addresses over TCP…"))
        }
        let timeout = request.tcpTimeout
        var denied = false

        await withTaskGroup(of: (String, ScanEngine.Liveness, TimeInterval).self) { group in
            var next = 0
            var done = 0

            while next < pending.count && next < DiscoveryEngine.hostConcurrency {
                let address = pending[next]
                next += 1
                group.addTask {
                    await DiscoveryEngine.timedLiveness(address, timeout, deps)
                }
            }

            while let item = await group.next() {
                if Task.isCancelled { continue }
                let (address, liveness, elapsed) = item
                done += 1
                switch liveness {
                case .up:
                    await table.found(address, by: .tcp, latency: elapsed)
                case .denied:
                    denied = true
                case .down:
                    break
                }
                out.yield(.progress(0.2 + 0.7 * Double(done) / Double(pending.count)))
                if done % 16 == 0 && done < pending.count {
                    out.yield(.status("Checking quiet addresses over TCP… \(done) of \(pending.count)"))
                }

                if next < pending.count {
                    let upcoming = pending[next]
                    next += 1
                    group.addTask {
                        await DiscoveryEngine.timedLiveness(upcoming, timeout, deps)
                    }
                }
            }
        }
        if Task.isCancelled { return }
        if denied {
            out.yield(.permissionDenied)
        }
        out.yield(.progress(0.9))
        out.yield(.status("Listening for Bonjour devices…"))
    }

    private static func timedLiveness(
        _ address: String,
        _ timeout: TimeInterval,
        _ deps: ScanDependencies
    ) async -> (String, ScanEngine.Liveness, TimeInterval) {
        let started = ProcessInfo.processInfo.systemUptime
        let liveness = await ScanEngine.liveness(of: address, timeout: timeout, deps)
        return (address, liveness, ProcessInfo.processInfo.systemUptime - started)
    }

    private static func lookUpNames(
        _ deps: ScanDependencies,
        _ table: DeviceTable,
        _ out: AsyncStream<DiscoveryEvent>.Continuation
    ) async {
        let addresses = await table.addressesWithoutHostName()
        guard !addresses.isEmpty else { return }
        out.yield(.status("Looking up names…"))

        await withTaskGroup(of: (String, String?).self) { group in
            var next = 0
            var done = 0

            while next < addresses.count && next < DiscoveryEngine.nameConcurrency {
                let address = addresses[next]
                next += 1
                group.addTask {
                    (address, await deps.reverseName(address))
                }
            }

            while let item = await group.next() {
                if Task.isCancelled { continue }
                let (address, name) = item
                done += 1
                if let name = name {
                    await table.setHostName(name, for: address)
                }
                out.yield(.progress(0.9 + 0.1 * Double(done) / Double(addresses.count)))

                if next < addresses.count {
                    let upcoming = addresses[next]
                    next += 1
                    group.addTask {
                        (upcoming, await deps.reverseName(upcoming))
                    }
                }
            }
        }
    }
}

/// The devices found so far. Every change is reported as a .device event with
/// the device's full record.
private actor DeviceTable {
    private var devices: [String: Device] = [:]
    private let ownAddress: String?
    private let out: AsyncStream<DiscoveryEvent>.Continuation

    init(ownAddress: String?, out: AsyncStream<DiscoveryEvent>.Continuation) {
        self.ownAddress = ownAddress
        self.out = out
    }

    func found(_ address: String, by method: DiscoveryMethod, latency: TimeInterval?) {
        update(address) { device in
            device.methods.insert(method)
            if let latency = latency {
                device.latency = min(device.latency ?? latency, latency)
            }
        }
    }

    func add(_ service: BonjourService) {
        var service = service
        // The phone's own services resolve over loopback (127.0.0.1); file
        // them under its network address instead of inventing a device.
        if service.address.hasPrefix("127.") {
            guard let ownAddress = ownAddress else { return }
            service = service.moved(to: ownAddress)
        }
        update(service.address) { device in
            device.methods.insert(.bonjour)
            if !device.services.contains(service) {
                device.services.append(service)
            }
        }
    }

    func setHostName(_ name: String, for address: String) {
        var cleaned = name
        while cleaned.hasSuffix(".") {
            cleaned.removeLast()
        }
        guard !cleaned.isEmpty, cleaned != address else { return }
        update(address) { $0.hostName = cleaned }
    }

    func knownAddresses() -> Set<String> {
        Set(devices.keys)
    }

    func addressesWithoutHostName() -> [String] {
        devices.values
            .filter { $0.hostName == nil }
            .sorted { $0.sortKey < $1.sortKey }
            .map { $0.address }
    }

    private func update(_ address: String, _ change: (inout Device) -> Void) {
        var device = devices[address] ?? Device(address: address, isThisDevice: address == ownAddress)
        change(&device)
        devices[address] = device
        out.yield(.device(device))
    }
}
