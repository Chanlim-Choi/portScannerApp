import Foundation

/// The network the phone is currently on, used to pre-fill the target field.
enum LocalNetwork {
    struct Info: Sendable, Equatable {
        /// The phone's own address, for example 192.168.1.23.
        let address: String
        let prefix: Int
        /// The surrounding block, for example 192.168.1.0/24.
        let cidr: String
    }

    /// Reads the Wi-Fi (or Ethernet) interface. Returns nil when there is none.
    static func current() -> Info? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return nil }
        defer { freeifaddrs(head) }

        var fallback: Info?
        var cursor = head
        while let entry = cursor {
            cursor = entry.pointee.ifa_next

            let flags = Int32(entry.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            guard let addressPointer = entry.pointee.ifa_addr,
                  let maskPointer = entry.pointee.ifa_netmask,
                  addressPointer.pointee.sa_family == sa_family_t(AF_INET) else { continue }

            let name = String(cString: entry.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }

            let address = addressPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            let mask = maskPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            // Skip self-assigned 169.254.x.x addresses.
            guard (address >> 16) != 0xA9FE else { continue }

            let prefix = mask.nonzeroBitCount
            // The target parser takes at most a /20 (4096 addresses). On a wider
            // network, offer the /24 around the phone's own address instead.
            let scanPrefix = prefix >= 20 ? prefix : 24
            let scanMask = ~UInt32(0) << UInt32(32 - scanPrefix)
            let info = Info(
                address: TargetParser.ipString(address),
                prefix: prefix,
                cidr: "\(TargetParser.ipString(address & scanMask))/\(scanPrefix)"
            )
            // en0 is Wi-Fi on an iPhone.
            if name == "en0" { return info }
            if fallback == nil { fallback = info }
        }
        return fallback
    }
}

/// Hostname lookup through the system resolver.
enum Resolver {
    /// Returns one numeric address for the name, preferring IPv4.
    static func resolve(_ name: String) async -> String? {
        await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: Resolver.lookup(name))
            }
        }
    }

    private static func lookup(_ name: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &list) == 0 else { return nil }
        defer { freeaddrinfo(list) }

        var chosen: String?
        var cursor = list
        while let entry = cursor {
            cursor = entry.pointee.ai_next

            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let status = getnameinfo(
                entry.pointee.ai_addr,
                entry.pointee.ai_addrlen,
                &buffer,
                socklen_t(buffer.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard status == 0 else { continue }

            let text = String(cString: buffer)
            if entry.pointee.ai_family == AF_INET {
                return text
            }
            if chosen == nil {
                chosen = text
            }
        }
        return chosen
    }
}
