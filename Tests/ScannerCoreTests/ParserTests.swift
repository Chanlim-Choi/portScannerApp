import XCTest
@testable import ScannerCore

final class PortParserTests: XCTestCase {
    func testSinglePortsAndRanges() throws {
        XCTAssertEqual(try PortParser.parse("22,80,443"), [22, 80, 443])
        XCTAssertEqual(try PortParser.parse("1-5"), [1, 2, 3, 4, 5])
        XCTAssertEqual(try PortParser.parse(" 443 , 22 "), [22, 443])
    }

    func testDuplicatesAreMergedAndSorted() throws {
        XCTAssertEqual(try PortParser.parse("80,80,79-81"), [79, 80, 81])
        XCTAssertEqual(try PortParser.parse("443,22,22"), [22, 443])
    }

    func testOpenEndedRanges() throws {
        XCTAssertEqual(try PortParser.parse("-").count, 65535)
        XCTAssertEqual(try PortParser.parse("-3"), [1, 2, 3])
        XCTAssertEqual(try PortParser.parse("65533-"), [65533, 65534, 65535])
    }

    func testInvalidInputThrows() {
        for text in ["", "   ", "0", "65536", "70000", "5-1", "abc", "22,,x", "1-2-3"] {
            XCTAssertThrowsError(try PortParser.parse(text), "expected \"\(text)\" to be rejected")
        }
    }

    func testTopPortLists() {
        XCTAssertEqual(TopPorts.top100.count, 100)
        XCTAssertEqual(TopPorts.top1000.count, 1000)
        XCTAssertEqual(TopPorts.top100, TopPorts.top100.sorted())
        XCTAssertEqual(TopPorts.top1000, TopPorts.top1000.sorted())
        XCTAssertTrue(Set(TopPorts.top100).isSubset(of: Set(TopPorts.top1000)))
        for port: UInt16 in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080] {
            XCTAssertTrue(TopPorts.top100.contains(port), "top 100 should contain \(port)")
        }
    }
}

final class TargetParserTests: XCTestCase {
    /// Flattens parsed targets so they can be compared; hostnames get a "host:" prefix.
    private func expand(_ text: String) throws -> [String] {
        try TargetParser.parse(text).map { target -> String in
            switch target {
            case .address(let address):
                return address
            case .hostname(let name):
                return "host:" + name
            }
        }
    }

    func testSingleAddress() throws {
        XCTAssertEqual(try expand("10.0.0.5"), ["10.0.0.5"])
    }

    func testCIDRBlocks() throws {
        XCTAssertEqual(try expand("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(try expand("10.0.0.6/31"), ["10.0.0.6", "10.0.0.7"])
        XCTAssertEqual(try expand("10.0.0.9/32"), ["10.0.0.9"])

        // A host address with a prefix scans the whole surrounding block.
        let block = try expand("192.168.1.77/24")
        XCTAssertEqual(block.count, 254)
        XCTAssertEqual(block.first, "192.168.1.1")
        XCTAssertEqual(block.last, "192.168.1.254")

        XCTAssertEqual(try expand("10.0.0.0/20").count, 4094)
    }

    func testOctetRanges() throws {
        XCTAssertEqual(try expand("10.0.0.1-3"), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        XCTAssertEqual(try expand("10.0.0-1.1,5"), ["10.0.0.1", "10.0.0.5", "10.0.1.1", "10.0.1.5"])
        XCTAssertEqual(try expand("10.0.0.*").count, 256)

        // Open-ended octet ranges, as in nmap.
        let tail = try expand("10.0.0.250-")
        XCTAssertEqual(tail.count, 6)
        XCTAssertEqual(tail.first, "10.0.0.250")
        XCTAssertEqual(tail.last, "10.0.0.255")
        XCTAssertEqual(try expand("10.0.0.-2"), ["10.0.0.0", "10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(try expand("10.0.0.-").count, 256)
    }

    func testFullAddressRanges() throws {
        XCTAssertEqual(try expand("10.0.0.1-10.0.0.3"), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        XCTAssertEqual(try expand("10.0.0.254-10.0.1.1"), ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"])
        XCTAssertThrowsError(try TargetParser.parse("10.0.0.5-10.0.0.1"))
        XCTAssertThrowsError(try TargetParser.parse("10.0.0.0-10.0.255.255"))
    }

    func testHostnamesAndIPv6() throws {
        XCTAssertEqual(try expand("Router.LAN"), ["host:router.lan"])
        XCTAssertEqual(try expand("a.lan,b.lan"), ["host:a.lan", "host:b.lan"])
        XCTAssertEqual(try expand("::1"), ["::1"])
        XCTAssertEqual(try expand("fe80::1%en0"), ["fe80::1%en0"])
        XCTAssertEqual(try expand("2001:db8::10"), ["2001:db8::10"])
    }

    func testSeveralTargetsAreDeduplicated() throws {
        XCTAssertEqual(try expand("10.0.0.1 10.0.0.1 10.0.0.2"), ["10.0.0.1", "10.0.0.2"])
        XCTAssertEqual(try expand("10.0.0.1-2 10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
    }

    func testInvalidTargetsThrow() {
        let typos = ["192.168.1", "50", "-", "10.0.0.1 - 50", "a.lan,192.168"]
        for text in ["", "   ", "10.0.0.256", "10.0.0.5-1", "10.0.0.0/33", "10.0.0/24", "bad!host", ":::1::", "1.2.3.4.5/24"] + typos {
            XCTAssertThrowsError(try TargetParser.parse(text), "expected \"\(text)\" to be rejected")
        }
    }

    func testOversizedRangesThrow() {
        for text in ["10.0.0.0/8", "10.0.0.0/19", "10.0.0-255.*"] {
            XCTAssertThrowsError(try TargetParser.parse(text), "expected \"\(text)\" to be too large")
        }
    }
}

final class ServiceNameTests: XCTestCase {
    func testKnownAndUnknownPorts() {
        XCTAssertEqual(ServiceNames.name(for: 22), "ssh")
        XCTAssertEqual(ServiceNames.name(for: 80), "http")
        XCTAssertEqual(ServiceNames.name(for: 443), "https")
        XCTAssertEqual(ServiceNames.name(for: 1), "tcpmux")
        XCTAssertEqual(ServiceNames.name(for: 62078), "iphone-sync")
        XCTAssertEqual(ServiceNames.name(for: 12346), "")
    }

    func testPortResultUsesServiceName() {
        XCTAssertEqual(PortResult(port: 3389, state: .open).service, "ms-wbt-server")
    }
}
