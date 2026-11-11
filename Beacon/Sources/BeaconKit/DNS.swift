// BeaconKit — the minimal DNS responder the dev Beacon needs (BCN-024): parse a query's first
// question and answer A/AAAA/TXT for names under the Beacon's domain (A → the configured address),
// NXDOMAIN-free (an empty NOERROR answer) for other types. Enough for an OAST lookup to arrive and
// be recorded; it is not a general DNS server.

import Foundation

/// A DNS question.
public struct DNSQuestion: Sendable, Hashable {
    /// The queried name, without the trailing dot.
    public var name: String
    /// QTYPE (1 = A, 28 = AAAA, 16 = TXT…).
    public var type: UInt16
    /// The transaction id.
    public var id: UInt16

    /// The type's mnemonic.
    public var typeName: String {
        switch type {
        case 1: "A"
        case 2: "NS"
        case 5: "CNAME"
        case 15: "MX"
        case 16: "TXT"
        case 28: "AAAA"
        default: "TYPE\(type)"
        }
    }
}

/// Query parsing and answer building.
public enum DNSCodec {
    /// The first question of a query packet; nil when malformed.
    public static func question(_ packet: [UInt8]) -> DNSQuestion? {
        guard packet.count >= 17 else { return nil }
        let id = UInt16(packet[0]) << 8 | UInt16(packet[1])
        let questions = UInt16(packet[4]) << 8 | UInt16(packet[5])
        guard questions >= 1 else { return nil }
        var index = 12
        var labels: [String] = []
        while index < packet.count {
            let length = Int(packet[index])
            if length == 0 {
                index += 1
                break
            }
            // Queries carry no compression pointers.
            guard length < 64, index + 1 + length <= packet.count else { return nil }
            labels.append(String(decoding: packet[(index + 1)..<(index + 1 + length)], as: UTF8.self))
            index += 1 + length
        }
        guard index + 4 <= packet.count else { return nil }
        let type = UInt16(packet[index]) << 8 | UInt16(packet[index + 1])
        return DNSQuestion(name: labels.joined(separator: "."), type: type, id: id)
    }

    /// The answer to `query` (the original packet): for an A question, `address` (IPv4) with a 60 s
    /// TTL; for TXT, "gulp-beacon"; otherwise no records. Authoritative, recursion not available.
    public static func answer(_ query: [UInt8], question: DNSQuestion, address: [UInt8]) -> [UInt8] {
        // Echo the header and the question section.
        var end = 12
        while end < query.count, query[end] != 0 { end += Int(query[end]) + 1 }
        end = min(query.count, end + 5)
        var reply = Array(query[0..<end])
        reply[2] = 0x84 | (query[2] & 0x01)  // QR, AA, keep RD
        reply[3] = 0x00  // RA = 0, RCODE = NOERROR
        reply[4] = 0
        reply[5] = 1  // QDCOUNT 1
        var records: [[UInt8]] = []
        let pointer: [UInt8] = [0xC0, 0x0C]  // the name at offset 12
        if question.type == 1, address.count == 4 {
            records.append(pointer + [0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + address)
        } else if question.type == 16 {
            let text = Array("gulp-beacon".utf8)
            records.append(
                pointer + [0, 16, 0, 1, 0, 0, 0, 60, 0, UInt8(text.count + 1), UInt8(text.count)] + text)
        }
        reply[6] = 0
        reply[7] = UInt8(records.count)  // ANCOUNT
        reply[8] = 0
        reply[9] = 0
        reply[10] = 0
        reply[11] = 0
        return reply + records.flatMap { $0 }
    }

    /// A query packet for `name` and `type` (for tests and VulnLab's simulated lookups).
    public static func query(_ name: String, type: UInt16 = 1, id: UInt16 = 0x4755) -> [UInt8] {
        var packet: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            packet.append(UInt8(bytes.count))
            packet += bytes
        }
        packet += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0, 1]
        return packet
    }
}
