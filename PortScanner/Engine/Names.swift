import Foundation

/// DNS names in the forms the reverse lookup needs.
enum DNSName {
    /// "192.168.1.20" becomes "20.1.168.192.in-addr.arpa.", the name a PTR
    /// (reverse) query asks about.
    static func reverseIPv4(_ address: String) -> String? {
        guard let value = TargetParser.ipv4Value(address) else { return nil }
        let octets = [value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, value >> 24]
        return octets.map { String($0) }.joined(separator: ".") + ".in-addr.arpa."
    }

    /// Decodes a name in DNS wire format (length-prefixed labels ending in a
    /// zero byte), as found in the data of a PTR record. Returns it with a
    /// trailing dot, or nil if the bytes are not a well-formed name.
    static func decode(_ bytes: [UInt8]) -> String? {
        var labels: [String] = []
        var index = 0
        while index < bytes.count {
            let length = Int(bytes[index])
            index += 1
            if length == 0 {
                return labels.isEmpty ? nil : labels.joined(separator: ".") + "."
            }
            // 64 and above are compression pointers or reserved values, which
            // the system resolver never hands back in record data.
            guard length < 64, index + length <= bytes.count else { return nil }
            labels.append(String(decoding: bytes[index..<(index + length)], as: UTF8.self))
            index += length
        }
        return nil
    }
}

/// Plain names for Apple's model identifiers ("Mac14,2", "AudioAccessory5,1").
enum AppleModel {
    static func family(_ identifier: String) -> String? {
        let letters = String(identifier.prefix { $0.isLetter })
        let numbers = identifier.dropFirst(letters.count)
        let parts = numbers.split(separator: ",", omittingEmptySubsequences: false)
        guard !letters.isEmpty, parts.count == 2,
              let major = Int(parts[0]), Int(parts[1]) != nil else {
            return nil
        }
        switch letters {
        case "AudioAccessory": return major == 5 ? "HomePod mini" : "HomePod"
        case "AppleTV": return "Apple TV"
        case "MacBookPro": return "MacBook Pro"
        case "MacBookAir": return "MacBook Air"
        case "MacBook": return "MacBook"
        case "Macmini": return "Mac mini"
        case "MacPro": return "Mac Pro"
        case "iMac", "iMacPro": return "iMac"
        case "Mac": return "Mac"
        case "iPhone": return "iPhone"
        case "iPad": return "iPad"
        case "iPod": return "iPod touch"
        default: return nil
        }
    }
}
