import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Builds and reads the few DNS messages the app needs.
enum DNSMessage {
    static let typePTR: UInt16 = 12
    static let classIN: UInt16 = 1

    /// A standard query for the PTR record of `name` ("20.1.168.192.in-addr.arpa.").
    static func ptrQuery(id: UInt16, name: String) -> [UInt8] {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let utf8 = Array(label.utf8.prefix(63))
            bytes.append(UInt8(utf8.count))
            bytes += utf8
        }
        bytes.append(0)
        bytes += [UInt8(typePTR >> 8), UInt8(typePTR & 0xFF), UInt8(classIN >> 8), UInt8(classIN & 0xFF)]
        return bytes
    }

    /// The target of the first PTR record in the answer section of a response
    /// to query `id`, with a trailing dot; nil for anything else.
    static func ptrAnswer(_ bytes: [UInt8], id: UInt16) -> String? {
        guard bytes.count >= 12,
              word(bytes, 0) == id,
              bytes[2] & 0x80 != 0 else {
            return nil
        }
        let questions = Int(word(bytes, 4))
        let answers = Int(word(bytes, 6))
        var offset = 12
        for _ in 0..<questions {
            guard let (_, next) = readName(bytes, at: offset), next + 4 <= bytes.count else { return nil }
            offset = next + 4
        }
        for _ in 0..<answers {
            guard let (_, next) = readName(bytes, at: offset), next + 10 <= bytes.count else { return nil }
            let type = word(bytes, next)
            let length = Int(word(bytes, next + 8))
            let dataStart = next + 10
            guard dataStart + length <= bytes.count else { return nil }
            if type == typePTR, let (name, _) = readName(bytes, at: dataStart), name != "." {
                return name
            }
            offset = dataStart + length
        }
        return nil
    }

    /// Reads a name that may use compression pointers. Returns it with a
    /// trailing dot, and the offset just after the name where it started.
    static func readName(_ bytes: [UInt8], at offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var position = offset
        var resumeAt: Int?
        var jumps = 0
        while position < bytes.count {
            let length = Int(bytes[position])
            if length == 0 {
                let name = labels.isEmpty ? "." : labels.joined(separator: ".") + "."
                return (name, resumeAt ?? position + 1)
            }
            if length & 0xC0 == 0xC0 {
                // A pointer to a name earlier in the message.
                guard position + 1 < bytes.count, jumps < 16 else { return nil }
                if resumeAt == nil {
                    resumeAt = position + 2
                }
                position = ((length & 0x3F) << 8) | Int(bytes[position + 1])
                jumps += 1
                continue
            }
            guard length < 64, position + 1 + length <= bytes.count else { return nil }
            labels.append(String(decoding: bytes[(position + 1)..<(position + 1 + length)], as: UTF8.self))
            position += 1 + length
        }
        return nil
    }

    private static func word(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
    }
}

#if canImport(Glibc)
private let udpSocketType = Int32(SOCK_DGRAM.rawValue)
#else
private let udpSocketType = SOCK_DGRAM
#endif

/// Asks a device directly, by unicast UDP to its port 5353, for the name of
/// its own address. Bonjour responders answer such queries (RFC 6762, legacy
/// unicast), and some answer these but not the system's multicast query.
/// Unlike multicast, this needs no special entitlement on iOS.
enum DirectMDNS {
    static func reverseName(_ address: String, port: UInt16 = 5353, timeout: TimeInterval) async -> String? {
        let flag = CancellationFlag()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
                DispatchQueue.global(qos: .utility).async {
                    continuation.resume(returning: DirectMDNS.query(address, port: port, timeout: timeout, flag: flag))
                }
            }
        } onCancel: {
            flag.cancel()
        }
    }

    private static func query(_ address: String, port: UInt16, timeout: TimeInterval, flag: CancellationFlag) -> String? {
        guard let queryName = DNSName.reverseIPv4(address),
              var destination = Pinger.makeSocketAddress(address) else {
            return nil
        }
        destination.sin_port = port.bigEndian

        let fd = socket(AF_INET, udpSocketType, Int32(IPPROTO_UDP))
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        let id = UInt16.random(in: 1...UInt16.max)
        let packet = DNSMessage.ptrQuery(id: id, name: queryName)
        let sent = packet.withUnsafeBytes { bytes in
            withUnsafePointer(to: &destination) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    sendto(fd, bytes.baseAddress, bytes.count, 0, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent >= 0 else { return nil }

        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var buffer = [UInt8](repeating: 0, count: 1500)
        while !flag.isCancelled {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining <= 0 { return nil }
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&descriptor, 1, Int32(min(remaining, 0.1) * 1000)) > 0 else { continue }

            var source = sockaddr_in()
            var sourceLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let count = buffer.withUnsafeMutableBytes { bytes in
                withUnsafeMutablePointer(to: &source) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                        recvfrom(fd, bytes.baseAddress, bytes.count, 0, socketAddress, &sourceLength)
                    }
                }
            }
            guard count > 0, source.sin_addr.s_addr == destination.sin_addr.s_addr else { continue }
            if let name = DNSMessage.ptrAnswer(Array(buffer[0..<count]), id: id) {
                return name
            }
        }
        return nil
    }
}
