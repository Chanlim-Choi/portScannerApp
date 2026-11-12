import SwiftUI

@MainActor
final class ScanViewModel: ObservableObject {
    // Inputs, bound to the form.
    @Published var targetText = ""
    @Published var preset: PortPreset = .standard
    @Published var customPorts = "22,80,443"
    @Published var timing: TimingTemplate = .normal
    @Published var skipDiscovery = false
    @Published var errorMessage: String?
    @Published private(set) var errorTitle = "Check the input"

    // Outputs.
    @Published private(set) var isScanning = false
    @Published private(set) var progress = 0.0
    @Published private(set) var status = ""
    @Published private(set) var summary: String?
    @Published private(set) var notes: [String] = []
    @Published private(set) var hosts: [HostResult] = []
    @Published private(set) var permissionDenied = false
    @Published private(set) var localNetwork: LocalNetwork.Info?

    private var task: Task<Void, Never>?
    private var unresolvedCount = 0
    private var discoveredUp: Int?
    private var interruptionNote: String?

    init() {
        localNetwork = LocalNetwork.current()
    }

    var canStart: Bool {
        !isScanning && !targetText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func refreshLocalNetwork() {
        localNetwork = LocalNetwork.current()
    }

    func start() {
        guard canStart else { return }

        let request: ScanRequest
        do {
            let targets = try TargetParser.parse(targetText)
            let ports = try selectedPorts()
            request = ScanRequest(targets: targets, ports: ports, timing: timing, skipDiscovery: skipDiscovery)
        } catch {
            errorTitle = "Check the input"
            errorMessage = error.localizedDescription
            return
        }

        hosts = []
        notes = []
        summary = nil
        permissionDenied = false
        unresolvedCount = 0
        discoveredUp = nil
        interruptionNote = nil
        progress = 0
        status = "Starting…"
        isScanning = true
        KeepAwake.begin()

        let started = Date()
        task = Task { [weak self] in
            for await event in ScanEngine.run(request, using: .live) {
                self?.apply(event)
            }
            self?.finish(started: started, stopped: Task.isCancelled)
        }
    }

    /// Scans one address straight away, for example from the device list.
    func scan(_ address: String, preset: PortPreset) {
        if isScanning {
            errorTitle = "A scan is already running"
            errorMessage = "Stop the current scan first, then scan this device again."
            return
        }
        targetText = address
        self.preset = preset
        start()
    }

    func stop() {
        task?.cancel()
    }

    /// iOS suspends apps soon after they leave the screen, which would leave the
    /// probes in flight looking "filtered". Stop cleanly instead.
    func appMovedToBackground() {
        guard isScanning else { return }
        interruptionNote = "The scan stopped because the app left the screen. iOS pauses apps in the background, so scan again to finish."
        stop()
    }

    private func selectedPorts() throws -> [UInt16] {
        switch preset {
        case .quick:
            return TopPorts.top100
        case .standard:
            return TopPorts.top1000
        case .all:
            return Array(1...65535)
        case .custom:
            return try PortParser.parse(customPorts)
        }
    }

    private func apply(_ event: ScanEvent) {
        switch event {
        case .status(let text):
            status = text

        case .unresolved(let name):
            unresolvedCount += 1
            notes.append("Could not resolve \(name).")

        case .discovered(let up, let total):
            discoveredUp = up
            if up == total {
                notes.append("All \(total) addresses answered.")
            } else {
                notes.append("\(up) of \(total) addresses answered; the rest were skipped. Turn on Skip host discovery to scan them anyway.")
            }

        case .hostStarted(let id, let label, let address):
            hosts.append(HostResult(id: id, label: label, address: address))

        case .port(let hostID, let port, let state):
            guard let index = hosts.firstIndex(where: { $0.id == hostID }) else { return }
            let result = PortResult(port: port, state: state)
            // Results arrive out of order; keep the list sorted by port.
            let position = hosts[index].ports.firstIndex(where: { $0.port > port }) ?? hosts[index].ports.endIndex
            hosts[index].ports.insert(result, at: position)

        case .hostFinished(let id, let closed, let filtered):
            guard let index = hosts.firstIndex(where: { $0.id == id }) else { return }
            hosts[index].closedCount = closed
            hosts[index].filteredCount = filtered
            hosts[index].isFinished = true

        case .progress(let value):
            progress = value

        case .permissionDenied:
            permissionDenied = true
        }
    }

    private func finish(started: Date, stopped: Bool) {
        isScanning = false
        task = nil
        status = ""
        KeepAwake.end()

        // A host still in progress when the scan was stopped has partial results.
        for index in hosts.indices where !hosts[index].isFinished {
            hosts[index].wasStopped = true
        }

        let seconds = String(format: "%.1f", Date().timeIntervalSince(started))
        let openPorts = hosts.reduce(0) { $0 + $1.openCount }
        let verb = stopped ? "Stopped after" : "Finished in"
        let hostWord = hosts.count == 1 ? "host" : "hosts"
        let portWord = openPorts == 1 ? "open port" : "open ports"
        summary = "\(verb) \(seconds) s: \(hosts.count) \(hostWord), \(openPorts) \(portWord)."

        if let note = interruptionNote {
            notes.append(note)
        }

        let anythingAnswered = hosts.contains { $0.responded }
        guard !stopped, !anythingAnswered, !permissionDenied else { return }

        if hosts.isEmpty && discoveredUp == nil {
            // No connection was attempted: every name failed to resolve.
            if unresolvedCount > 0 {
                notes.append("None of the names could be resolved. Check the spelling, or enter an IP address.")
            }
        } else if let up = discoveredUp, up > 0 {
            notes.append("The hosts are up, but none of the chosen ports answered.")
        } else {
            notes.append("Nothing answered. If iOS just asked for Local Network access, tap Allow and scan again. Otherwise the devices may be offline or firewalled.")
        }
    }
}
