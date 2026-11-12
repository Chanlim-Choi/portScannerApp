import Foundation
import Network

/// Browses the local network for the service types in BonjourCatalog and
/// resolves each service it finds to an IPv4 address.
final class BonjourBrowser: @unchecked Sendable {
    /// Seconds allowed for resolving one service to an address.
    private static let resolveTimeout: TimeInterval = 3

    // All state below is used only on this queue.
    private let queue = DispatchQueue(label: "portscanner.bonjour")
    private var browsers: [NWBrowser] = []
    private var resolving: [String: NWConnection] = [:]
    private var seen: Set<String> = []
    /// _device-info TXT records waiting for their host's address, by instance name.
    private var deviceInfo: [String: [String: String]] = [:]
    /// Addresses learned from other services, by (cleaned) instance name.
    private var addressByName: [String: String] = [:]
    private var continuation: AsyncStream<BonjourService>.Continuation?
    private var browsing = false
    private var finished = false

    /// Listens for `duration` seconds, then finishes once the services found
    /// so far are resolved. Ending the stream early stops everything.
    static func browse(for duration: TimeInterval) -> AsyncStream<BonjourService> {
        AsyncStream(BonjourService.self) { continuation in
            let browser = BonjourBrowser()
            browser.queue.async {
                browser.start(continuation, duration: duration)
            }
            continuation.onTermination = { _ in
                browser.queue.async {
                    browser.finish()
                }
            }
        }
    }

    private func start(_ continuation: AsyncStream<BonjourService>.Continuation, duration: TimeInterval) {
        guard !finished else { return }
        self.continuation = continuation
        browsing = true

        for entry in BonjourCatalog.types {
            let parameters = NWParameters()
            parameters.includePeerToPeer = false
            let browser = NWBrowser(for: .bonjourWithTXTRecord(type: entry.type, domain: "local."), using: parameters)
            browser.browseResultsChangedHandler = { [weak self] _, changes in
                for change in changes {
                    if case .added(let result) = change {
                        self?.resolve(result)
                    }
                }
            }
            browser.start(queue: queue)
            browsers.append(browser)
        }

        queue.asyncAfter(deadline: .now() + duration) { [weak self] in
            self?.stopBrowsing()
        }
    }

    private func resolve(_ result: NWBrowser.Result) {
        guard !finished, case let .service(name, type, domain, _) = result.endpoint else { return }
        let key = "\(name)|\(type)|\(domain)"
        guard seen.insert(key).inserted else { return }

        var txt: [String: String] = [:]
        if case let .bonjour(record) = result.metadata {
            txt = record.dictionary
        }

        if type == "_device-info._tcp" {
            // Announced on port 0, so it can never be resolved by connecting.
            // It only carries the host's model, and uses the same instance
            // name as the host's other services, so attach it by name.
            if let address = addressByName[name] {
                yieldDeviceInfo(name: name, txt: txt, address: address)
            } else {
                deviceInfo[name] = txt
            }
            return
        }

        // Starting a connection is how Network.framework resolves a service.
        // UDP is used even for TCP services: a UDP "connection" is ready as
        // soon as the name resolves, sends nothing, and needs no listener, so
        // services on placeholder ports (such as _workstation on port 9)
        // resolve too. IPv4 keeps the address in line with the rest of the app.
        let parameters = NWParameters.udp
        if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = .v4
        }
        let connection = NWConnection(to: result.endpoint, using: parameters)
        resolving[key] = connection
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready, .waiting:
                self?.resolved(key, connection, name: name, type: type, txt: txt)
            case .failed, .cancelled:
                self?.drop(key)
            default:
                break
            }
        }
        connection.start(queue: queue)

        queue.asyncAfter(deadline: .now() + BonjourBrowser.resolveTimeout) { [weak self] in
            self?.drop(key)
        }
    }

    private func resolved(_ key: String, _ connection: NWConnection, name: String, type: String, txt: [String: String]) {
        guard resolving[key] != nil else { return }
        // Until the name resolves, the remote endpoint is still the service
        // itself; then keep waiting (up to the timeout).
        guard case let .hostPort(host, port)? = connection.currentPath?.remoteEndpoint,
              case let .ipv4(ipv4) = host else {
            return
        }
        let address = ipv4.rawValue.map { String($0) }.joined(separator: ".")
        let service = BonjourService(
            name: name,
            type: type,
            address: address,
            port: port.rawValue,
            friendlyName: txt["fn"],
            model: txt["model"] ?? txt["md"] ?? txt["am"] ?? txt["ty"]
        )
        continuation?.yield(service)

        let instance = BonjourCatalog.displayName(instance: name, type: type)
        if addressByName[instance] == nil {
            addressByName[instance] = address
        }
        if let waiting = deviceInfo.removeValue(forKey: instance) {
            yieldDeviceInfo(name: instance, txt: waiting, address: address)
        }
        drop(key)
    }

    private func yieldDeviceInfo(name: String, txt: [String: String], address: String) {
        continuation?.yield(BonjourService(
            name: name,
            type: "_device-info._tcp",
            address: address,
            port: nil,
            friendlyName: nil,
            model: txt["model"]
        ))
    }

    private func drop(_ key: String) {
        guard let connection = resolving.removeValue(forKey: key) else { return }
        connection.stateUpdateHandler = nil
        connection.cancel()
        if !browsing && resolving.isEmpty {
            finish()
        }
    }

    private func stopBrowsing() {
        guard browsing else { return }
        browsing = false
        browsers.forEach { $0.cancel() }
        browsers = []
        if resolving.isEmpty {
            finish()
        }
    }

    private func finish() {
        guard !finished else { return }
        finished = true
        browsing = false
        browsers.forEach { $0.cancel() }
        browsers = []
        for connection in resolving.values {
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
        resolving = [:]
        continuation?.finish()
        continuation = nil
    }
}
