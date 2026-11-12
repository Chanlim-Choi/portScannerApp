import SwiftUI

@MainActor
final class DiscoveryViewModel: ObservableObject {
    @Published private(set) var devices: [Device] = []
    @Published private(set) var isRunning = false
    @Published private(set) var progress = 0.0
    @Published private(set) var status = ""
    @Published private(set) var summary: String?
    @Published private(set) var notes: [String] = []
    @Published private(set) var permissionDenied = false
    @Published private(set) var network: LocalNetwork.Info?

    private var task: Task<Void, Never>?
    private var interruptionNote: String?

    init() {
        network = LocalNetwork.current()
    }

    func refreshNetwork() {
        if !isRunning {
            network = LocalNetwork.current()
        }
    }

    func device(at address: String) -> Device? {
        devices.first { $0.address == address }
    }

    func start() {
        guard !isRunning else { return }
        network = LocalNetwork.current()
        guard let network = network else {
            summary = nil
            notes = ["Connect to Wi-Fi to look for devices on your network."]
            return
        }

        let addresses: [String]
        do {
            addresses = try TargetParser.parse(network.cidr).compactMap { target -> String? in
                if case .address(let address) = target {
                    return address
                }
                return nil
            }
        } catch {
            notes = [error.localizedDescription]
            return
        }

        devices = []
        notes = []
        summary = nil
        permissionDenied = false
        interruptionNote = nil
        progress = 0
        status = "Starting…"
        isRunning = true
        KeepAwake.begin()

        let request = DiscoveryRequest(addresses: addresses, ownAddress: network.address)
        let started = Date()
        task = Task { [weak self] in
            for await event in DiscoveryEngine.run(request, using: .live) {
                self?.apply(event)
            }
            self?.finish(started: started, stopped: Task.isCancelled)
        }
    }

    func stop() {
        task?.cancel()
    }

    func appMovedToBackground() {
        guard isRunning else { return }
        interruptionNote = "The search stopped because the app left the screen. Search again to finish."
        stop()
    }

    private func apply(_ event: DiscoveryEvent) {
        switch event {
        case .status(let text):
            status = text

        case .progress(let value):
            progress = value

        case .device(let device):
            if let index = devices.firstIndex(where: { $0.address == device.address }) {
                devices[index] = device
            } else {
                let position = devices.firstIndex(where: { $0.sortKey > device.sortKey }) ?? devices.endIndex
                devices.insert(device, at: position)
            }

        case .pingUnavailable:
            notes.append("Ping is not available, so devices were found with TCP and Bonjour only.")

        case .permissionDenied:
            permissionDenied = true
        }
    }

    private func finish(started: Date, stopped: Bool) {
        isRunning = false
        task = nil
        status = ""
        KeepAwake.end()

        let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
        let verb = stopped ? "Stopped after" : "Finished in"
        let word = devices.count == 1 ? "device" : "devices"
        summary = "\(verb) \(seconds) s: \(devices.count) \(word) found."
        if let note = interruptionNote {
            notes.append(note)
        }
    }
}
