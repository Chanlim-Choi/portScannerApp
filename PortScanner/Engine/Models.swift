import Foundation

/// Port states, named the way nmap names them for a TCP connect scan.
enum PortState: String, Sendable {
    /// The connection was accepted.
    case open
    /// The host actively refused the connection.
    case closed
    /// Nothing came back before the timeout (dropped, firewalled or offline).
    case filtered
}

/// The outcome of one connection attempt, before it is turned into a PortState.
enum ProbeResult: Sendable {
    case open
    case closed
    case filtered
    /// iOS refused the connection because Local Network access is not granted.
    case denied
}

struct PortResult: Identifiable, Hashable, Sendable {
    let port: UInt16
    let state: PortState

    var id: UInt16 { port }
    var service: String { ServiceNames.name(for: port) }
}

struct HostResult: Identifiable, Sendable {
    let id: Int
    /// What the user typed: a hostname or an IP address.
    let label: String
    /// The IP address that was actually scanned.
    let address: String
    var ports: [PortResult] = []
    var closedCount = 0
    var filteredCount = 0
    var isFinished = false
    /// The scan was stopped before this host's results were complete.
    var wasStopped = false

    var title: String {
        label == address ? address : "\(label) (\(address))"
    }

    var openCount: Int {
        ports.filter { $0.state == .open }.count
    }

    /// True when at least one port answered, open or refused.
    var responded: Bool {
        openCount > 0 || closedCount > 0
    }

    var footnote: String {
        "\(closedCount) closed, \(filteredCount) filtered"
    }
}

/// Speed presets, loosely modelled on nmap's -T templates.
enum TimingTemplate: String, CaseIterable, Identifiable, Sendable {
    case polite
    case normal
    case aggressive
    case insane

    var id: String { rawValue }

    var title: String {
        switch self {
        case .polite: return "Polite (T2)"
        case .normal: return "Normal (T3)"
        case .aggressive: return "Aggressive (T4)"
        case .insane: return "Insane (T5)"
        }
    }

    /// Connections in flight at once.
    var concurrency: Int {
        switch self {
        case .polite: return 20
        case .normal: return 100
        case .aggressive: return 200
        case .insane: return 300
        }
    }

    /// Seconds to wait for an answer before calling a port filtered.
    var timeout: TimeInterval {
        switch self {
        case .polite: return 2.5
        case .normal: return 1.0
        case .aggressive: return 0.7
        case .insane: return 0.4
        }
    }

    /// Extra attempts for a port that did not answer.
    var retries: Int {
        switch self {
        case .polite, .normal, .aggressive: return 1
        case .insane: return 0
        }
    }
}

enum PortPreset: String, CaseIterable, Identifiable, Sendable {
    case quick
    case standard
    case all
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .quick: return "Quick (top 100)"
        case .standard: return "Standard (top 1000)"
        case .all: return "All (1-65535)"
        case .custom: return "Custom"
        }
    }
}
