import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// ICMP echo ("ping") messages, built and read by hand.
enum ICMPPacket {
    static let echoRequestType: UInt8 = 8
    static let echoReplyType: UInt8 = 0

    struct EchoReply: Equatable {
        let identifier: UInt16
        let sequence: UInt16
    }

    /// The Internet checksum (RFC 1071).
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count {
            sum += UInt32(bytes[index]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum)
    }

    static func echoRequest(identifier: UInt16, sequence: UInt16, payload: [UInt8]) -> [UInt8] {
        var packet: [UInt8] = [
            echoRequestType, 0, 0, 0,
            UInt8(identifier >> 8), UInt8(identifier & 0xFF),
            UInt8(sequence >> 8), UInt8(sequence & 0xFF),
        ]
        packet += payload
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8)
        packet[3] = UInt8(sum & 0xFF)
        return packet
    }

    /// Reads an echo reply. Apple systems hand ICMP datagram sockets the whole
    /// IPv4 packet and Linux only the ICMP message, so a leading IPv4 header is
    /// skipped when there is one.
    static func parseEchoReply(_ bytes: [UInt8]) -> EchoReply? {
        var offset = 0
        if let first = bytes.first, first >> 4 == 4 {
            offset = Int(first & 0x0F) * 4
            guard offset >= 20 else { return nil }
        }
        guard bytes.count >= offset + 8,
              bytes[offset] == echoReplyType,
              bytes[offset + 1] == 0 else {
            return nil
        }
        let identifier = (UInt16(bytes[offset + 4]) << 8) | UInt16(bytes[offset + 5])
        let sequence = (UInt16(bytes[offset + 6]) << 8) | UInt16(bytes[offset + 7])
        return EchoReply(identifier: identifier, sequence: sequence)
    }
}

#if canImport(Glibc)
private let datagramSocketType = Int32(SOCK_DGRAM.rawValue)
#else
private let datagramSocketType = SOCK_DGRAM
#endif

/// Pings many IPv4 addresses from one socket and collects who answers. It uses
/// an unprivileged ICMP datagram socket, which iOS and macOS let apps open
/// (Linux too, when net.ipv4.ping_group_range allows it).
enum Pinger {
    /// Sequence numbers encode round * maxTargets + index.
    static let maxTargets = 4096
    static let maxRounds = 15

    /// Returns the round-trip time in seconds for each address that answered.
    /// Addresses that did not answer are asked again on the next round, up to
    /// `rounds` times. Anything that is not an IPv4 address is ignored. Returns
    /// nil when no ICMP socket could be opened.
    static func sweep(_ addresses: [String], timeout: TimeInterval, rounds: Int = 2) async -> [String: TimeInterval]? {
        let flag = CancellationFlag()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<[String: TimeInterval]?, Never>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    continuation.resume(returning: Pinger.run(addresses, timeout: timeout, rounds: rounds, flag: flag))
                }
            }
        } onCancel: {
            flag.cancel()
        }
    }

    static func makeSocketAddress(_ text: String) -> sockaddr_in? {
        var address = sockaddr_in()
        #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        let status = text.withCString { inet_pton(AF_INET, $0, &address.sin_addr) }
        return status == 1 ? address : nil
    }

    private static func run(
        _ addresses: [String],
        timeout: TimeInterval,
        rounds: Int,
        flag: CancellationFlag
    ) -> [String: TimeInterval]? {
        let fd = socket(AF_INET, datagramSocketType, Int32(IPPROTO_ICMP))
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // Room for a few hundred replies arriving together.
        var receiveBufferSize: Int32 = 256 * 1024
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveBufferSize, socklen_t(MemoryLayout<Int32>.size))

        var targets: [(address: String, socketAddress: sockaddr_in)] = []
        for address in addresses.prefix(maxTargets) {
            if let socketAddress = makeSocketAddress(address) {
                targets.append((address, socketAddress))
            }
        }

        let identifier = UInt16.random(in: 1...UInt16.max)
        let payload = Array("PortScanner ping".utf8)
        var sentAt: [UInt16: TimeInterval] = [:]
        var results: [String: TimeInterval] = [:]
        var buffer = [UInt8](repeating: 0, count: 2048)

        // Reads one reply if one arrives within `wait` seconds (at most 0.1 s,
        // so cancellation is noticed quickly).
        func receive(wait: TimeInterval) {
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let milliseconds = Int32(max(0, min(wait, 0.1)) * 1000)
            guard poll(&descriptor, 1, milliseconds) > 0 else { return }

            var source = sockaddr_in()
            var sourceLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let count = buffer.withUnsafeMutableBytes { bytes in
                withUnsafeMutablePointer(to: &source) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                        recvfrom(fd, bytes.baseAddress, bytes.count, 0, socketAddress, &sourceLength)
                    }
                }
            }
            guard count > 0, let reply = ICMPPacket.parseEchoReply(Array(buffer[0..<count])) else { return }
            #if !os(Linux)
            // Linux rewrites the identifier on these sockets and delivers only
            // this socket's replies; Apple systems need the check.
            guard reply.identifier == identifier else { return }
            #endif
            guard let sent = sentAt[reply.sequence] else { return }
            let index = Int(reply.sequence) % maxTargets
            guard index < targets.count else { return }
            let target = targets[index]
            guard source.sin_addr.s_addr == target.socketAddress.sin_addr.s_addr,
                  results[target.address] == nil else {
                return
            }
            results[target.address] = uptime() - sent
        }

        var anySent = false
        for round in 0..<min(max(rounds, 1), maxRounds) {
            for (index, target) in targets.enumerated() {
                if flag.isCancelled { return results }
                guard results[target.address] == nil else { continue }

                let sequence = UInt16(round * maxTargets + index)
                let packet = ICMPPacket.echoRequest(identifier: identifier, sequence: sequence, payload: payload)
                var destination = target.socketAddress
                sentAt[sequence] = uptime()
                let sent = packet.withUnsafeBytes { bytes in
                    withUnsafePointer(to: &destination) { pointer in
                        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                            sendto(fd, bytes.baseAddress, bytes.count, 0, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }
                if sent >= 0 {
                    anySent = true
                }
                // Collect early replies while sending, and pace the burst.
                receive(wait: 0)
                if index % 16 == 15 {
                    usleep(2_000)
                }
            }

            // Every send refused (no route, or iOS blocking local network
            // access): ping is not usable here, which is not the same as
            // nobody answering.
            if !anySent && !targets.isEmpty {
                return nil
            }

            let deadline = uptime() + timeout
            while results.count < targets.count && !flag.isCancelled {
                let remaining = deadline - uptime()
                if remaining <= 0 { break }
                receive(wait: remaining)
            }
        }
        return results
    }

    private static func uptime() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime
    }
}

/// A thread-safe "stop" flag for blocking work that runs outside Swift tasks.
final class CancellationFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }
}
