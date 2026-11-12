import XCTest
@testable import ScannerCore

final class DNSNameTests: XCTestCase {
    func testReverseNameOfIPv4() {
        XCTAssertEqual(DNSName.reverseIPv4("192.168.1.20"), "20.1.168.192.in-addr.arpa.")
        XCTAssertEqual(DNSName.reverseIPv4("10.0.0.1"), "1.0.0.10.in-addr.arpa.")
        XCTAssertNil(DNSName.reverseIPv4("nas.local"))
        XCTAssertNil(DNSName.reverseIPv4("::1"))
    }

    func testDecodesWireFormat() {
        let bytes: [UInt8] = [3] + Array("nas".utf8) + [5] + Array("local".utf8) + [0]
        XCTAssertEqual(DNSName.decode(bytes), "nas.local.")
    }

    func testRejectsMalformedNames() {
        XCTAssertNil(DNSName.decode([]))
        XCTAssertNil(DNSName.decode([0]), "the root name alone is not a device name")
        XCTAssertNil(DNSName.decode([5] + Array("ab".utf8)), "label runs past the end")
        XCTAssertNil(DNSName.decode([3] + Array("nas".utf8)), "missing the final zero")
        XCTAssertNil(DNSName.decode([0xC0, 0x0C]), "compression pointer")
    }
}

final class AppleModelTests: XCTestCase {
    func testKnownFamilies() {
        XCTAssertEqual(AppleModel.family("Mac14,2"), "Mac")
        XCTAssertEqual(AppleModel.family("MacBookPro18,3"), "MacBook Pro")
        XCTAssertEqual(AppleModel.family("MacBookAir10,1"), "MacBook Air")
        XCTAssertEqual(AppleModel.family("Macmini9,1"), "Mac mini")
        XCTAssertEqual(AppleModel.family("iMac21,1"), "iMac")
        XCTAssertEqual(AppleModel.family("AudioAccessory5,1"), "HomePod mini")
        XCTAssertEqual(AppleModel.family("AudioAccessory6,1"), "HomePod")
        XCTAssertEqual(AppleModel.family("AppleTV11,1"), "Apple TV")
        XCTAssertEqual(AppleModel.family("iPhone15,2"), "iPhone")
        XCTAssertEqual(AppleModel.family("iPad13,1"), "iPad")
    }

    func testOtherStringsAreLeftAlone() {
        XCTAssertNil(AppleModel.family("Google Home Mini"))
        XCTAssertNil(AppleModel.family("HP LaserJet Pro M404"))
        XCTAssertNil(AppleModel.family("Mac"))
        XCTAssertNil(AppleModel.family("Sonos One,2"))
        XCTAssertNil(AppleModel.family(""))
    }
}
