import Foundation

/// Minimal STUN (RFC 5389) Binding client codec: learn the public IP:port a NAT assigned to a socket.
public enum Stun {
    public static let magicCookie: UInt32 = 0x2112A442
    static let bindingRequestType: UInt16 = 0x0001
    static let bindingSuccessType: UInt16 = 0x0101
    static let attrMappedAddress: UInt16 = 0x0001
    static let attrXorMappedAddress: UInt16 = 0x0020

    public enum MappingBehavior: Equatable {
        /// Same public port for every destination: hole punching normally works.
        case endpointIndependent
        /// Different public port per destination: hole punching usually fails.
        case symmetric
        case unknown
    }

    public static func newTransactionID() -> Data {
        Data((0..<12).map { _ in UInt8.random(in: 0...255) })
    }

    public static func bindingRequest(transactionID: Data) -> Data {
        precondition(transactionID.count == 12, "STUN transaction IDs are 12 bytes")
        var w = ByteWriter()
        w.u16(bindingRequestType)
        w.u16(0)
        w.u32(magicCookie)
        w.bytes(transactionID)
        return w.data
    }

    public static func parseBindingResponse(_ data: Data, transactionID: Data) throws -> Endpoint {
        do {
            return try parse(data, transactionID: transactionID)
        } catch {
            throw DollyError.badStunResponse
        }
    }

    /// Compare the mapped endpoints different STUN servers reported for the same local socket.
    public static func mappingBehavior(_ results: [Endpoint]) -> MappingBehavior {
        guard results.count >= 2 else { return .unknown }
        return results.allSatisfy { $0 == results[0] } ? .endpointIndependent : .symmetric
    }

    private static func parse(_ data: Data, transactionID: Data) throws -> Endpoint {
        var r = ByteReader(data)
        guard try r.u16() == bindingSuccessType else { throw DollyError.badStunResponse }
        let length = Int(try r.u16())
        guard try r.u32() == magicCookie else { throw DollyError.badStunResponse }
        guard try r.bytes(12) == transactionID else { throw DollyError.badStunResponse }
        var attributes = ByteReader(try r.bytes(length))

        var plainMapped: Endpoint?
        while attributes.remaining >= 4 {
            let type = try attributes.u16()
            let valueLength = Int(try attributes.u16())
            let value = try attributes.bytes(valueLength)
            _ = try attributes.bytes(min((4 - valueLength % 4) % 4, attributes.remaining))  // padding
            switch type {
            case attrXorMappedAddress:
                return try decodeAddress(value, xor: true, transactionID: transactionID)
            case attrMappedAddress:
                plainMapped = try decodeAddress(value, xor: false, transactionID: transactionID)
            default:
                break
            }
        }
        guard let plainMapped else { throw DollyError.badStunResponse }
        return plainMapped
    }

    private static func decodeAddress(_ value: Data, xor: Bool, transactionID: Data) throws -> Endpoint {
        var r = ByteReader(value)
        _ = try r.u8()
        let family = try r.u8()
        var port = try r.u16()
        var maskWriter = ByteWriter()
        maskWriter.u32(magicCookie)
        maskWriter.bytes(transactionID)
        let mask = [UInt8](maskWriter.data)
        if xor { port ^= UInt16(magicCookie >> 16) }

        let length: Int
        switch family {
        case 1: length = 4
        case 2: length = 16
        default: throw DollyError.badStunResponse
        }
        var address = [UInt8](try r.bytes(length))
        if xor { for i in 0..<length { address[i] ^= mask[i] } }
        return try Endpoint(kind: family == 1 ? .v4 : .v6, address: Data(address), port: port)
    }
}
