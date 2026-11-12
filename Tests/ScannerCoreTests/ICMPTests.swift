import XCTest
@testable import ScannerCore

final class ICMPPacketTests: XCTestCase {
    func testChecksumMatchesRFC1071Example() {
        // RFC 1071 section 3: these words sum to 0xDDF2, so the checksum is 0x220D.
        XCTAssertEqual(ICMPPacket.checksum([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]), 0x220D)
    }

    func testChecksumOfOddLength() {
        XCTAssertEqual(ICMPPacket.checksum([0x01]), ~UInt16(0x0100))
    }

    func testEchoRequestLayoutAndChecksum() {
        let packet = ICMPPacket.echoRequest(identifier: 0xBEEF, sequence: 0x0102, payload: [9, 8, 7])
        XCTAssertEqual(packet.count, 11)
        XCTAssertEqual(packet[0], 8, "echo request type")
        XCTAssertEqual(packet[1], 0, "code")
        XCTAssertEqual(Array(packet[4...7]), [0xBE, 0xEF, 0x01, 0x02])
        XCTAssertEqual(Array(packet[8...]), [9, 8, 7])
        // A message with a correct checksum sums to zero.
        XCTAssertEqual(ICMPPacket.checksum(packet), 0)
    }

    private func reply(identifier: UInt16, sequence: UInt16) -> [UInt8] {
        var packet = ICMPPacket.echoRequest(identifier: identifier, sequence: sequence, payload: [1, 2, 3, 4])
        packet[0] = ICMPPacket.echoReplyType
        return packet
    }

    func testParsesReplyWithoutIPHeader() {
        XCTAssertEqual(
            ICMPPacket.parseEchoReply(reply(identifier: 7, sequence: 300)),
            ICMPPacket.EchoReply(identifier: 7, sequence: 300)
        )
    }

    func testParsesReplyAfterIPv4Header() {
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x45
        XCTAssertEqual(
            ICMPPacket.parseEchoReply(header + reply(identifier: 0x1234, sequence: 4097)),
            ICMPPacket.EchoReply(identifier: 0x1234, sequence: 4097)
        )

        // A header with options (IHL 6 = 24 bytes) is skipped too.
        var longHeader = [UInt8](repeating: 0, count: 24)
        longHeader[0] = 0x46
        XCTAssertEqual(
            ICMPPacket.parseEchoReply(longHeader + reply(identifier: 1, sequence: 2)),
            ICMPPacket.EchoReply(identifier: 1, sequence: 2)
        )
    }

    func testRejectsOtherMessages() {
        let request = ICMPPacket.echoRequest(identifier: 1, sequence: 1, payload: [])
        XCTAssertNil(ICMPPacket.parseEchoReply(request), "an echo request is not a reply")
        XCTAssertNil(ICMPPacket.parseEchoReply([0, 0, 0]), "too short")
        var unreachable = reply(identifier: 1, sequence: 1)
        unreachable[0] = 3
        XCTAssertNil(ICMPPacket.parseEchoReply(unreachable), "destination unreachable")
        XCTAssertNil(ICMPPacket.parseEchoReply([0x45] + [UInt8](repeating: 0, count: 10)), "header longer than the data")
    }
}

final class PingerTests: XCTestCase {
    func testPingsLoopback() async throws {
        guard let replies = await Pinger.sweep(["127.0.0.1", "not-an-address"], timeout: 1) else {
            throw XCTSkip("This system does not allow unprivileged ICMP sockets.")
        }
        let latency = try XCTUnwrap(replies["127.0.0.1"], "loopback should answer")
        XCTAssertGreaterThanOrEqual(latency, 0)
        XCTAssertLessThan(latency, 1)
        XCTAssertNil(replies["not-an-address"])
    }

    func testCancellationStopsTheSweep() async throws {
        // 192.0.2.0/24 is reserved for documentation, so nothing answers.
        let addresses = (1...20).map { "192.0.2.\($0)" }
        let started = Date()
        let sweep = Task { await Pinger.sweep(addresses, timeout: 5, rounds: 3) }
        try await Task.sleep(nanoseconds: 300_000_000)
        sweep.cancel()
        let replies = await sweep.value
        guard let replies = replies else {
            throw XCTSkip("This system does not allow unprivileged ICMP sockets.")
        }
        XCTAssertTrue(replies.isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3, "cancelling should end the sweep quickly")
    }
}
