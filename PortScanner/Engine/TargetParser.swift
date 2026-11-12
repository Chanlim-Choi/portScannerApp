import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(WinSDK)
import WinSDK
#endif

enum ScanTarget: Hashable, Sendable {
    /// A literal IPv4 or IPv6 address.
    case address(String)
    /// A name that still has to be resolved.
    case hostname(String)
}

/// Parses nmap-style target lists:
///   10.0.0.5            a single address
///   10.0.0.0/24         a CIDR block
///   10.0.0.1-50         octet ranges and lists (10.0.0-2.1,5,10-20, 10.0.0.100-)
///   10.0.0.1-10.0.0.20  a range written as two full addresses
///   router.example.com  a hostname
/// Several targets are separated by spaces.
enum TargetParser {
    static let maxHosts = 4096

    enum ParseError: LocalizedError {
        case empty
        case invalid(String)
        case tooMany

        var errorDescription: String? {
            switch self {
            case .empty:
                return "Enter an IP address, a hostname, a CIDR block or a range."
            case .invalid(let token):
                return "\"\(token)\" is not a valid target."
            case .tooMany:
                return "That is more than \(TargetParser.maxHosts) addresses. Narrow the range."
            }
        }
    }

    static func parse(_ text: String) throws -> [ScanTarget] {
        let tokens = text.split(whereSeparator: { $0.isWhitespace }).map { String($0) }
        var targets: [ScanTarget] = []
        var seen = Set<ScanTarget>()
        for token in tokens {
            for target in try expand(token) {
                guard seen.insert(target).inserted else { continue }
                targets.append(target)
                if targets.count > maxHosts { throw ParseError.tooMany }
            }
        }
        guard !targets.isEmpty else { throw ParseError.empty }
        return targets
    }

    private static func expand(_ token: String) throws -> [ScanTarget] {
        if token.contains("/") {
            return try expandCIDR(token)
        }
        if let addresses = try expandAddressRange(token) {
            return addresses
        }
        if let addresses = try expandOctetRanges(token) {
            return addresses
        }
        if token.contains(":") {
            guard isIPv6(token) else { throw ParseError.invalid(token) }
            return [ScanTarget.address(token)]
        }
        if token.contains(",") {
            var result: [ScanTarget] = []
            for piece in token.split(separator: ",") {
                result.append(contentsOf: try expand(String(piece)))
            }
            return result
        }
        // A DNS name never has an all-numeric top-level label, so a token made
        // only of digits, dots and dashes is a mistyped address or range (for
        // example "192.168.1"). Reject it rather than let the resolver guess.
        if token.allSatisfy({ "0123456789.-".contains($0) }) {
            throw ParseError.invalid(token)
        }
        guard isHostname(token) else { throw ParseError.invalid(token) }
        return [ScanTarget.hostname(token.lowercased())]
    }

    /// "10.0.0.1-10.0.0.20": a range written as two full addresses. Returns
    /// nil when the token is not in that form.
    private static func expandAddressRange(_ token: String) throws -> [ScanTarget]? {
        let ends = token.split(separator: "-", omittingEmptySubsequences: false)
        guard ends.count == 2,
              let low = ipv4Value(String(ends[0])),
              let high = ipv4Value(String(ends[1])) else {
            return nil
        }
        guard low <= high else { throw ParseError.invalid(token) }
        guard high - low < UInt32(maxHosts) else { throw ParseError.tooMany }
        return (low...high).map { ScanTarget.address(ipString($0)) }
    }

    /// Returns nil when the token does not look like an IPv4 address at all, so
    /// the caller can try it as a hostname.
    private static func expandOctetRanges(_ token: String) throws -> [ScanTarget]? {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        let allowed = Set("0123456789-,*")
        let looksLikeIPv4 = parts.count == 4 && parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { allowed.contains($0) }
        }
        guard looksLikeIPv4 else { return nil }

        var octets: [[UInt32]] = []
        var total = 1
        for part in parts {
            let values = try parseOctet(String(part), token: token)
            total *= values.count
            guard total <= maxHosts else { throw ParseError.tooMany }
            octets.append(values)
        }

        var result: [ScanTarget] = []
        result.reserveCapacity(total)
        for a in octets[0] {
            for b in octets[1] {
                for c in octets[2] {
                    for d in octets[3] {
                        result.append(ScanTarget.address("\(a).\(b).\(c).\(d)"))
                    }
                }
            }
        }
        return result
    }

    private static func parseOctet(_ text: String, token: String) throws -> [UInt32] {
        if text == "*" {
            return Array(0...255)
        }
        var values: [UInt32] = []
        for item in text.split(separator: ",") {
            let bounds = item.split(separator: "-", omittingEmptySubsequences: false)
            switch bounds.count {
            case 1:
                guard let value = UInt32(bounds[0]), value <= 255 else {
                    throw ParseError.invalid(token)
                }
                values.append(value)
            case 2:
                // As in nmap, a missing end means 0 or 255 ("100-", "-20", "-").
                let low: UInt32? = bounds[0].isEmpty ? 0 : UInt32(bounds[0])
                let high: UInt32? = bounds[1].isEmpty ? 255 : UInt32(bounds[1])
                guard let low = low, let high = high, low <= high, high <= 255 else {
                    throw ParseError.invalid(token)
                }
                values.append(contentsOf: low...high)
            default:
                throw ParseError.invalid(token)
            }
        }
        guard !values.isEmpty else { throw ParseError.invalid(token) }
        return values
    }

    private static func expandCIDR(_ token: String) throws -> [ScanTarget] {
        let pieces = token.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2,
              let prefix = Int(pieces[1]), prefix >= 0, prefix <= 32,
              let base = ipv4Value(String(pieces[0])) else {
            throw ParseError.invalid(token)
        }
        let hostBits = 32 - prefix
        guard hostBits < 20, (1 << hostBits) <= maxHosts else { throw ParseError.tooMany }

        let size = UInt32(1) << UInt32(hostBits)
        let network = base & ~(size - 1)
        // Leave out the network and broadcast addresses when the block has them.
        let first: UInt32 = hostBits >= 2 ? 1 : 0
        let last: UInt32 = hostBits >= 2 ? size - 2 : size - 1
        var result: [ScanTarget] = []
        result.reserveCapacity(Int(last - first + 1))
        for offset in first...last {
            result.append(ScanTarget.address(ipString(network + offset)))
        }
        return result
    }

    static func ipv4Value(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt32(part), octet <= 255 else { return nil }
            value = (value << 8) | octet
        }
        return value
    }

    static func ipString(_ value: UInt32) -> String {
        "\(value >> 24).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
    }

    /// Accepts an IPv6 literal, optionally with a zone such as fe80::1%en0.
    private static func isIPv6(_ text: String) -> Bool {
        let literal = String(text.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)[0])
        var storage = in6_addr()
        return literal.withCString { inet_pton(AF_INET6, $0, &storage) } == 1
    }

    private static func isHostname(_ text: String) -> Bool {
        guard !text.isEmpty, text.count <= 253 else { return false }
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._")
        return text.allSatisfy { allowed.contains($0) }
    }
}
