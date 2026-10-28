import CryptoKit
import Foundation

/// One UDP datagram of the transport layer. Every frame carries a 16-byte tag keyed by the
/// handshake-derived transport key, so forged, spoofed or reflected datagrams are dropped before
/// they reach the ratchet.
///
/// ```
/// 0xD0 | kind(1) | senderIsInitiator(1) | body | tag(16)
/// punch / punchAck : nonce(8)
/// data             : seq(4) | ackNext(4) | sack(4) | payload (an encrypted session packet)
/// ack              : ackNext(4) | sack(4)
/// tag = HMAC-SHA256(transportKey, "dolly/v1/frame" || all bytes before the tag)[0..<16]
/// ```
public enum Frame: Equatable {
    public static let magic: UInt8 = 0xD0
    static let tagLength = 16
    static let domain = Data("dolly/v1/frame".utf8)

    enum Kind: UInt8 {
        case punch = 1, punchAck = 2, data = 3, ack = 4
    }

    case punch(nonce: Data)
    case punchAck(nonce: Data)
    case data(seq: UInt32, ackNext: UInt32, sack: UInt32, payload: Data)
    case ack(ackNext: UInt32, sack: UInt32)

    public func encoded(key: Data, isInitiator: Bool) -> Data {
        let kind: Kind
        var body = ByteWriter()
        switch self {
        case .punch(let nonce):
            precondition(nonce.count == 8)
            kind = .punch
            body.bytes(nonce)
        case .punchAck(let nonce):
            precondition(nonce.count == 8)
            kind = .punchAck
            body.bytes(nonce)
        case .data(let seq, let ackNext, let sack, let payload):
            kind = .data
            body.u32(seq)
            body.u32(ackNext)
            body.u32(sack)
            body.bytes(payload)
        case .ack(let ackNext, let sack):
            kind = .ack
            body.u32(ackNext)
            body.u32(sack)
        }
        var w = ByteWriter()
        w.u8(Frame.magic)
        w.u8(kind.rawValue)
        w.u8(isInitiator ? 1 : 0)
        w.bytes(body.data)
        return w.data + Frame.tag(key: key, over: w.data)
    }

    /// Verifies the tag, rejects frames that claim our own role (reflection), then parses.
    public static func decode(_ datagram: Data, key: Data, localIsInitiator: Bool) throws -> Frame {
        guard datagram.count >= 3 + tagLength else { throw DollyError.truncated }
        let signed = Data(datagram.prefix(datagram.count - tagLength))
        guard signed[signed.startIndex] == magic else { throw DollyError.malformedPacket }
        guard constantTimeEquals(Data(datagram.suffix(tagLength)), tag(key: key, over: signed)) else {
            throw DollyError.authenticationFailed
        }

        var r = ByteReader(signed)
        _ = try r.u8()
        guard let kind = Kind(rawValue: try r.u8()) else { throw DollyError.malformedPacket }
        let senderRole = try r.u8()
        guard senderRole <= 1, (senderRole == 1) != localIsInitiator else { throw DollyError.malformedPacket }

        switch kind {
        case .punch, .punchAck:
            let nonce = try r.bytes(8)
            guard r.remaining == 0 else { throw DollyError.malformedPacket }
            return kind == .punch ? .punch(nonce: nonce) : .punchAck(nonce: nonce)
        case .data:
            let seq = try r.u32()
            let ackNext = try r.u32()
            let sack = try r.u32()
            guard r.remaining > 0 else { throw DollyError.malformedPacket }
            return .data(seq: seq, ackNext: ackNext, sack: sack, payload: try r.bytes(r.remaining))
        case .ack:
            let ackNext = try r.u32()
            let sack = try r.u32()
            guard r.remaining == 0 else { throw DollyError.malformedPacket }
            return .ack(ackNext: ackNext, sack: sack)
        }
    }

    static func tag(key: Data, over bytes: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: domain + bytes, using: SymmetricKey(data: key))
        return Data(mac.prefix(tagLength))
    }

    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for (x, y) in zip(a, b) { difference |= x ^ y }
        return difference == 0
    }
}
