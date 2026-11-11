import Foundation
import Network

/// One TCP connect attempt: the same test `nmap -sT` performs. iOS does not
/// allow raw sockets, so a full connect is the only TCP scan available.
final class TCPProbe: @unchecked Sendable {
    // Every probe reports on this one serial queue, so the mutable state below
    // needs no locking.
    private static let queue = DispatchQueue(label: "portscanner.probe")

    private let connection: NWConnection
    private let timeout: TimeInterval
    private var continuation: CheckedContinuation<ProbeResult, Never>?
    private var timeoutItem: DispatchWorkItem?
    private var cancelled = false

    private init(address: String, port: UInt16, timeout: TimeInterval) {
        self.connection = NWConnection(
            host: NWEndpoint.Host(address),
            port: NWEndpoint.Port(integerLiteral: port),
            using: .tcp
        )
        self.timeout = timeout
    }

    static func run(address: String, port: UInt16, timeout: TimeInterval) async -> ProbeResult {
        let probe = TCPProbe(address: address, port: port, timeout: timeout)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<ProbeResult, Never>) in
                TCPProbe.queue.async { probe.start(continuation) }
            }
        } onCancel: {
            TCPProbe.queue.async { probe.cancel() }
        }
    }

    private func start(_ continuation: CheckedContinuation<ProbeResult, Never>) {
        if cancelled {
            continuation.resume(returning: .filtered)
            return
        }
        self.continuation = continuation
        connection.stateUpdateHandler = { state in
            self.handle(state)
        }
        connection.start(queue: TCPProbe.queue)

        // Weak, and cancelled in finish(), so a probe that is answered quickly
        // is freed straight away instead of living until its timeout.
        let timer = DispatchWorkItem { [weak self] in
            self?.finish(.filtered)
        }
        timeoutItem = timer
        TCPProbe.queue.asyncAfter(deadline: .now() + timeout, execute: timer)
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            finish(.open)
        case .waiting(let error):
            // A refused connection is reported as "waiting", not "failed".
            if connection.currentPath?.unsatisfiedReason == .localNetworkDenied {
                finish(.denied)
            } else {
                finish(TCPProbe.isRefusal(error) ? .closed : .filtered)
            }
        case .failed(let error):
            finish(TCPProbe.isRefusal(error) ? .closed : .filtered)
        case .cancelled:
            finish(.filtered)
        default:
            break
        }
    }

    private func finish(_ result: ProbeResult) {
        guard let continuation = continuation else { return }
        self.continuation = nil
        timeoutItem?.cancel()
        timeoutItem = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        continuation.resume(returning: result)
    }

    private func cancel() {
        cancelled = true
        finish(.filtered)
    }

    private static func isRefusal(_ error: NWError) -> Bool {
        if case .posix(let code) = error {
            return code == .ECONNREFUSED || code == .ECONNRESET
        }
        return false
    }
}

/// Each connection in flight holds a file descriptor and iOS starts an app
/// with a low limit, so raise it before scanning.
enum FileDescriptorLimit {
    static func raise(to target: rlim_t = 2048) {
        var limit = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limit) == 0 else { return }
        let wanted = min(target, limit.rlim_max)
        if limit.rlim_cur < wanted {
            limit.rlim_cur = wanted
            _ = setrlimit(RLIMIT_NOFILE, &limit)
        }
    }
}
