import Foundation

/// The Bonjour (mDNS) service types the app looks for, with plain names.
///
/// iOS only lets an app browse the types listed under NSBonjourServices in its
/// Info.plist, so every type here must also be in PortScanner-Info.plist (a
/// unit test checks that the two lists match).
enum BonjourCatalog {
    static let types: [(type: String, title: String)] = [
        ("_companion-link._tcp", "Apple device"),
        ("_device-info._tcp", "Device information"),
        ("_airplay._tcp", "AirPlay"),
        ("_raop._tcp", "AirPlay speaker"),
        ("_homekit._tcp", "Home hub"),
        ("_hap._tcp", "HomeKit accessory"),
        ("_hap._udp", "HomeKit accessory (Thread)"),
        ("_matter._tcp", "Matter device"),
        ("_matterc._udp", "Matter device (pairing)"),
        ("_googlecast._tcp", "Google Cast"),
        ("_spotify-connect._tcp", "Spotify Connect"),
        ("_sonos._tcp", "Sonos"),
        ("_amzn-wplay._tcp", "Amazon Fire TV"),
        ("_androidtvremote2._tcp", "Android TV"),
        ("_ipp._tcp", "Printer (IPP)"),
        ("_ipps._tcp", "Printer (IPPS)"),
        ("_printer._tcp", "Printer (LPD)"),
        ("_pdl-datastream._tcp", "Printer (raw)"),
        ("_uscan._tcp", "Scanner"),
        ("_scanner._tcp", "Scanner (legacy)"),
        ("_smb._tcp", "File sharing (SMB)"),
        ("_afpovertcp._tcp", "File sharing (AFP)"),
        ("_nfs._tcp", "File sharing (NFS)"),
        ("_adisk._tcp", "Time Machine disk"),
        ("_ssh._tcp", "SSH"),
        ("_sftp-ssh._tcp", "SFTP"),
        ("_rfb._tcp", "Screen sharing (VNC)"),
        ("_workstation._tcp", "Computer"),
        ("_http._tcp", "Web page"),
        ("_https._tcp", "Web page (HTTPS)"),
        ("_home-assistant._tcp", "Home Assistant"),
        ("_hue._tcp", "Philips Hue bridge"),
        ("_esphomelib._tcp", "ESPHome device"),
        ("_mqtt._tcp", "MQTT broker"),
        ("_daap._tcp", "Music library"),
        ("_airport._tcp", "AirPort base station"),
        ("_sleep-proxy._udp", "Sleep proxy"),
    ]

    static func title(for type: String) -> String {
        types.first { $0.type == type }?.title ?? type
    }

    /// Lower is better when choosing which service names a device.
    static func nameRank(for type: String) -> Int {
        switch type {
        case "_companion-link._tcp", "_device-info._tcp":
            return 0
        case "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp":
            return 1
        case "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp":
            return 2
        case "_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp", "_adisk._tcp", "_workstation._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_rfb._tcp":
            return 3
        default:
            return 5
        }
    }

    /// Strips the hardware address some services put in their instance names.
    static func displayName(instance: String, type: String) -> String {
        switch type {
        case "_raop._tcp":
            // "A1B2C3D4E5F6@Living Room": hardware address, then the name.
            if let at = instance.firstIndex(of: "@") {
                return String(instance[instance.index(after: at)...])
            }
        case "_workstation._tcp":
            // "nas [00:11:22:33:44:55]": the name, then the hardware address.
            if let bracket = instance.range(of: " [", options: .backwards) {
                return String(instance[..<bracket.lowerBound])
            }
        default:
            break
        }
        return instance
    }
}
