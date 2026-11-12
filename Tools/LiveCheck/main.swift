// Runs the app's real networking code on a Mac, which shares iOS's networking
// stack (Network.framework, mDNSResponder, BSD sockets). Build it from the
// repository root on a Mac:
//
//   swiftc -O PortScanner/Engine/*.swift Tools/LiveCheck/main.swift -o /tmp/livecheck
//
// Commands (scan only networks you are allowed to test):
//   livecheck bonjour [seconds]        list Bonjour services and their addresses
//   livecheck names <ip>...            reverse names (Bonjour first, then DNS)
//   livecheck ping <ip>...             ICMP echo round-trip times
//   livecheck ports <ip> <ports>       TCP connect scan, e.g. 22,80,443,9
//   livecheck discover [cidr]          the Devices tab's full search
import Foundation

func printLine(_ text: String) {
    print(text)
    fflush(stdout)
}

func elapsed(since start: Date) -> String {
    String(format: "%.2f s", Date().timeIntervalSince(start))
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    printLine("usage: livecheck bonjour|names|ping|ports|discover …")
    exit(2)
}
let rest = Array(arguments.dropFirst())
let deps = ScanDependencies.live
let started = Date()

switch command {
case "bonjour":
    let seconds = rest.first.flatMap(Double.init) ?? 6
    var count = 0
    for await service in deps.browse(seconds) {
        count += 1
        let port = service.port.map { String($0) } ?? "-"
        let model = service.model.map { " model=\($0)" } ?? ""
        printLine("\(service.type)\t\(service.address):\(port)\t\(service.displayName)\(model)")
    }
    printLine("\(count) services in \(elapsed(since: started))")

case "names":
    for address in rest {
        let lookupStart = Date()
        let name = await deps.reverseName(address)
        printLine("\(address)\t\(name ?? "-")\t\(elapsed(since: lookupStart))")
    }

case "ping":
    if let replies = await deps.ping(rest, 1) {
        for address in rest {
            let text = replies[address].map { Device.format(latency: $0) } ?? "no reply"
            printLine("\(address)\t\(text)")
        }
    } else {
        printLine("ping unavailable (no ICMP socket, or every send failed)")
    }
    printLine("done in \(elapsed(since: started))")

case "ports":
    guard rest.count == 2, let ports = try? PortParser.parse(rest[1]) else {
        printLine("usage: livecheck ports <ip> <ports>")
        exit(2)
    }
    let request = ScanRequest(targets: [.address(rest[0])], ports: ports, timing: .normal, skipDiscovery: true)
    for await event in ScanEngine.run(request, using: deps) {
        switch event {
        case let .port(_, port, state):
            printLine("\(port)/tcp\t\(state.rawValue)\t\(ServiceNames.name(for: port))")
        case let .hostFinished(_, closed, filtered):
            printLine("closed: \(closed), filtered: \(filtered)")
        case .permissionDenied:
            printLine("local network access denied")
        default:
            break
        }
    }
    printLine("done in \(elapsed(since: started))")

case "discover":
    let network = LocalNetwork.current()
    guard let cidr = rest.first ?? network?.cidr,
          let targets = try? TargetParser.parse(cidr) else {
        printLine("no network found; pass a CIDR block")
        exit(2)
    }
    let addresses = targets.compactMap { target -> String? in
        if case let .address(address) = target {
            return address
        }
        return nil
    }
    printLine("searching \(cidr) (\(addresses.count) addresses)")
    var devices: [String: Device] = [:]
    for await event in DiscoveryEngine.run(DiscoveryRequest(addresses: addresses, ownAddress: network?.address), using: deps) {
        switch event {
        case let .device(device):
            devices[device.address] = device
        case let .status(text):
            printLine("… \(text)")
        case .pingUnavailable:
            printLine("ping unavailable")
        case .permissionDenied:
            printLine("local network access denied")
        case .progress:
            break
        }
    }
    for device in devices.values.sorted(by: { $0.sortKey < $1.sortKey }) {
        let services = Set(device.services.map { $0.type }).sorted().joined(separator: ",")
        printLine("\(device.subtitle)\t\(device.title)\t[\(device.methodsText)]\t\(services)")
    }
    printLine("\(devices.count) devices in \(elapsed(since: started))")

default:
    printLine("unknown command \(command)")
    exit(2)
}
