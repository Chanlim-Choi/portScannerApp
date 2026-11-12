import Foundation
import dnssd

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

    /// The name of the device at an IPv4 address. Two sources are asked at
    /// once: Bonjour (a multicast PTR query, which devices running Bonjour
    /// answer with their own name, such as "nas.local") and the system
    /// resolver, which for LAN addresses only asks the router's DNS. The
    /// Bonjour answer wins.
    static func reverseName(_ address: String, timeout: TimeInterval = 2) async -> String? {
        async let multicast = MulticastReverseLookup.name(for: address, timeout: timeout)
        async let unicast = unicastReverseName(address, timeout: timeout)
        if let name = await multicast {
            return name
        }
        return await unicast
    }

    /// getnameinfo, given up after `timeout` seconds (the call itself cannot
    /// be interrupted, and usually fails within milliseconds on a LAN).
    private static func unicastReverseName(_ address: String, timeout: TimeInterval) async -> String? {
        await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let once = ResumeOnce(continuation)
            DispatchQueue.global(qos: .utility).async {
                once.resume(returning: Resolver.reverseLookup(address))
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                once.resume(returning: nil)
            }
        }
    }

    private static func reverseLookup(_ address: String) -> String? {
        guard var socketAddress = Pinger.makeSocketAddress(address) else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &socketAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketPointer in
                getnameinfo(
                    socketPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size),
                    &host,
                    socklen_t(host.count),
                    nil,
                    0,
                    NI_NAMEREQD
                )
            }
        }
        guard status == 0 else { return nil }
        var name = String(cString: host)
        while name.hasSuffix(".") {
            name.removeLast()
        }
        return name.isEmpty || name == address ? nil : name
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

/// Resumes a continuation from whichever of several callbacks comes first.
private final class ResumeOnce<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?

    init(_ continuation: CheckedContinuation<Value, Never>) {
        self.continuation = continuation
    }

    func resume(returning value: Value) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}

/// Asks Bonjour for the PTR record of an IPv4 address, like
/// `dig -x <address> -p 5353 @224.0.0.251`. Uses the system's DNS-SD service,
/// which needs Local Network access but no NSBonjourServices entry.
enum MulticastReverseLookup {
    static func name(for address: String, timeout: TimeInterval) async -> String? {
        guard let queryName = DNSName.reverseIPv4(address) else { return nil }
        return await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            PTRQuery(name: queryName, continuation: continuation).start(timeout: timeout)
        }
    }
}

/// One multicast PTR query. Everything runs on one serial queue, which is also
/// where DNS-SD delivers its callbacks, so the state needs no lock.
private final class PTRQuery: @unchecked Sendable {
    private static let queue = DispatchQueue(label: "portscanner.ptr")

    private let name: String
    private var continuation: CheckedContinuation<String?, Never>?
    private var serviceRef: DNSServiceRef?

    init(name: String, continuation: CheckedContinuation<String?, Never>) {
        self.name = name
        self.continuation = continuation
    }

    func start(timeout: TimeInterval) {
        PTRQuery.queue.async {
            // The callback gets this object back through the context pointer;
            // the retain is balanced in finish().
            let context = Unmanaged.passRetained(self).toOpaque()
            var ref: DNSServiceRef?
            let error = DNSServiceQueryRecord(
                &ref,
                DNSServiceFlags(kDNSServiceFlagsForceMulticast),
                0,
                self.name,
                UInt16(kDNSServiceType_PTR),
                UInt16(kDNSServiceClass_IN),
                ptrQueryReply,
                context
            )
            guard error == DNSServiceErrorType(kDNSServiceErr_NoError), let ref = ref else {
                Unmanaged<PTRQuery>.fromOpaque(context).release()
                self.finish(nil)
                return
            }
            self.serviceRef = ref
            DNSServiceSetDispatchQueue(ref, PTRQuery.queue)
            PTRQuery.queue.asyncAfter(deadline: .now() + timeout) {
                self.finish(nil)
            }
        }
    }

    /// Runs on the queue. Only the first call has an effect.
    fileprivate func finish(_ result: String?) {
        if let ref = serviceRef {
            serviceRef = nil
            DNSServiceRefDeallocate(ref)
            Unmanaged.passUnretained(self).release()
        }
        guard let continuation = continuation else { return }
        self.continuation = nil
        continuation.resume(returning: result)
    }
}

private func ptrQueryReply(
    _ serviceRef: DNSServiceRef?,
    _ flags: DNSServiceFlags,
    _ interfaceIndex: UInt32,
    _ errorCode: DNSServiceErrorType,
    _ fullName: UnsafePointer<CChar>?,
    _ recordType: UInt16,
    _ recordClass: UInt16,
    _ dataLength: UInt16,
    _ data: UnsafeRawPointer?,
    _ ttl: UInt32,
    _ context: UnsafeMutableRawPointer?
) {
    guard let context = context else { return }
    let query = Unmanaged<PTRQuery>.fromOpaque(context).takeUnretainedValue()
    guard errorCode == DNSServiceErrorType(kDNSServiceErr_NoError),
          flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
          let data = data, dataLength > 0 else {
        return
    }
    let bytes = Array(UnsafeRawBufferPointer(start: data, count: Int(dataLength)))
    if let name = DNSName.decode(bytes) {
        query.finish(name)
    }
}
