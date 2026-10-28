import Foundation

public enum DollyError: Error, Equatable {
    case truncated, badVersion, badSuite, badSignature, expired, badEndpoint
    case sameIdentity, notReadyToSend, messageTooLarge
    case malformedPacket, authenticationFailed, tooManySkippedKeys
}

struct ByteWriter {
    var data = Data()
    mutating func u8(_ v: UInt8) { data.append(v) }
    mutating func u16(_ v: UInt16) { data.append(contentsOf: [UInt8(v >> 8), UInt8(v & 0xff)]) }
    mutating func u32(_ v: UInt32) {
        data.append(contentsOf: [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }
    mutating func u64(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((v >> UInt64(shift)) & 0xff)) }
    }
    mutating func bytes(_ d: Data) { data.append(d) }
}

struct ByteReader {
    private let data: Data
    private(set) var offset = 0
    init(_ data: Data) { self.data = data }

    var remaining: Int { data.count - offset }

    mutating func bytes(_ n: Int) throws -> Data {
        guard n >= 0, remaining >= n else { throw DollyError.truncated }
        let start = data.startIndex + offset
        offset += n
        return Data(data[start..<start + n])
    }
    mutating func u8() throws -> UInt8 { try bytes(1)[0] }
    mutating func u16() throws -> UInt16 {
        let b = try bytes(2)
        return UInt16(b[b.startIndex]) << 8 | UInt16(b[b.startIndex + 1])
    }
    mutating func u32() throws -> UInt32 {
        try bytes(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }
    mutating func u64() throws -> UInt64 {
        try bytes(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }
}

public extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var out = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        self = out
    }
}
