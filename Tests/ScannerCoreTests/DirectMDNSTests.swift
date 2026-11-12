import XCTest
@testable import ScannerCore
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

final class DNSMessageTests: XCTestCase {
    func testQueryLayout() {
        let query = DNSMessage.ptrQuery(id: 0xABCD, name: "20.1.168.192.in-addr.arpa.")
        XCTAssertEqual(Array(query[0..<12]), [0xAB, 0xCD, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        let question = Array(query[12...])
        var expected: [UInt8] = []
        for label in ["20", "1", "168", "192", "in-addr", "arpa"] {
            expected.append(UInt8(label.utf8.count))
            expected.append(contentsOf: Array(label.utf8))
        }
        expected.append(contentsOf: [0, 0, 12, 0, 1])
        XCTAssertEqual(question, expected)
    }

    func testReadsCompressedNames() {
        // "local." at offset 0, then "nas" + pointer to offset 0.
        var bytes: [UInt8] = [5]
        bytes.append(contentsOf: Array("local".utf8))
        bytes.append(contentsOf: [0, 3])
        bytes.append(contentsOf: Array("nas".utf8))
        bytes.append(contentsOf: [0xC0, 0x00])
        let (name, next) = DNSMessage.readName(bytes, at: 7)!
        XCTAssertEqual(name, "nas.local.")
        XCTAssertEqual(next, bytes.count, "continues after the pointer, not after the target")
    }

    func testRejectsPointerLoops() {
        XCTAssertNil(DNSMessage.readName([0xC0, 0x00], at: 0))
    }

    func testReadsPTRAnswer() {
        let query = DNSMessage.ptrQuery(id: 7, name: "237.2.168.192.in-addr.arpa.")
        let response = DNSResponder.response(to: query, answer: "UPDB003.local.")!
        XCTAssertEqual(DNSMessage.ptrAnswer(response, id: 7), "UPDB003.local.")
        XCTAssertNil(DNSMessage.ptrAnswer(response, id: 8), "wrong ID")
        XCTAssertNil(DNSMessage.ptrAnswer(query, id: 7), "a query is not a response")
        XCTAssertNil(DNSMessage.ptrAnswer(Array(response.prefix(20)), id: 7), "truncated")
    }
}

/// A tiny UDP DNS responder on 127.0.0.1 for testing DirectMDNS end to end.
private enum DNSResponder {
    /// Echoes the query's ID and question and adds one PTR answer whose owner
    /// name is a compression pointer to the question.
    static func response(to query: [UInt8], answer: String) -> [UInt8]? {
        guard query.count > 12 else { return nil }
        var bytes = Array(query[0..<2]) + [0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0]
        bytes += query[12...]
        var target: [UInt8] = []
        for label in answer.split(separator: ".") {
            target.append(UInt8(label.utf8.count))
            target += Array(label.utf8)
        }
        target.append(0)
        bytes += [0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 120, UInt8(target.count >> 8), UInt8(target.count & 0xFF)]
        bytes += target
        return bytes
    }

    /// Starts answering one query on a free port; returns the port.
    static func start(answer: String) -> UInt16? {
        #if canImport(Glibc)
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), 0)
        #else
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        #endif
        guard fd >= 0, var address = Pinger.makeSocketAddress("127.0.0.1") else { return nil }
        address.sin_port = 0
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            close(fd)
            return nil
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &length)
            }
        }
        let port = UInt16(bigEndian: address.sin_port)

        DispatchQueue.global().async {
            defer { close(fd) }
            var buffer = [UInt8](repeating: 0, count: 1500)
            var client = sockaddr_in()
            var clientLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let count = buffer.withUnsafeMutableBytes { bytes in
                withUnsafeMutablePointer(to: &client) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(fd, bytes.baseAddress, bytes.count, 0, $0, &clientLength)
                    }
                }
            }
            guard count > 0, let reply = response(to: Array(buffer[0..<count]), answer: answer) else { return }
            _ = reply.withUnsafeBytes { bytes in
                withUnsafePointer(to: &client) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, bytes.baseAddress, bytes.count, 0, $0, clientLength)
                    }
                }
            }
        }
        return port
    }
}

final class DirectMDNSTests: XCTestCase {
    func testAsksTheDeviceDirectly() async throws {
        let port = try XCTUnwrap(DNSResponder.start(answer: "printer.local."))
        let name = await DirectMDNS.reverseName("127.0.0.1", port: port, timeout: 2)
        XCTAssertEqual(name, "printer.local.")
    }

    func testGivesUpWhenNobodyAnswers() async {
        let started = Date()
        // Port 9 (discard) on loopback: nothing answers.
        let name = await DirectMDNS.reverseName("127.0.0.1", port: 9, timeout: 0.3)
        XCTAssertNil(name)
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
    }
}
