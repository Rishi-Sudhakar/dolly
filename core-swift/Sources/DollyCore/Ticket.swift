import CryptoKit
import Foundation

/// A device's long-term keys. The Ed25519 key signs tickets; the X25519 key is used in the handshake.
public struct Identity {
    public let signing: Curve25519.Signing.PrivateKey
    public let agreement: Curve25519.KeyAgreement.PrivateKey

    public init() {
        signing = Curve25519.Signing.PrivateKey()
        agreement = Curve25519.KeyAgreement.PrivateKey()
    }

    public init(signingSeed: Data, agreementSeed: Data) throws {
        signing = try Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed)
        agreement = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: agreementSeed)
    }
}

public struct Endpoint: Equatable {
    public enum Kind: UInt8 { case v4 = 4, v6 = 6 }
    public let kind: Kind
    public let address: Data
    public let port: UInt16

    public init(kind: Kind, address: Data, port: UInt16) throws {
        guard address.count == (kind == .v4 ? 4 : 16) else { throw DollyError.badEndpoint }
        self.kind = kind
        self.address = address
        self.port = port
    }
}

/// Signed, self-contained invitation to connect. Exchanged out of band (QR, RCS text, share sheet).
public struct Ticket: Equatable {
    public static let version: UInt8 = 1
    public static let suiteClassical: UInt8 = 1
    static let signatureDomain = Data("dolly/v1/ticket".utf8)
    static let maxEndpoints = 8

    public let identityKey: Data   // Ed25519, 32 bytes
    public let staticKey: Data     // X25519, 32 bytes
    public let ephemeralKey: Data  // X25519, 32 bytes, single-use
    public let expiry: UInt64      // unix seconds
    public let endpoints: [Endpoint]
    public let signature: Data     // Ed25519 over domain || body, 64 bytes

    public static func create(
        identity: Identity,
        ephemeral: Curve25519.KeyAgreement.PublicKey,
        endpoints: [Endpoint],
        expiry: UInt64
    ) throws -> Ticket {
        guard endpoints.count <= maxEndpoints else { throw DollyError.badEndpoint }
        let unsigned = Ticket(
            identityKey: identity.signing.publicKey.rawRepresentation,
            staticKey: identity.agreement.publicKey.rawRepresentation,
            ephemeralKey: ephemeral.rawRepresentation,
            expiry: expiry,
            endpoints: endpoints,
            signature: Data()
        )
        let signature = try identity.signing.signature(for: signatureDomain + unsigned.body)
        return Ticket(
            identityKey: unsigned.identityKey, staticKey: unsigned.staticKey,
            ephemeralKey: unsigned.ephemeralKey, expiry: expiry, endpoints: endpoints, signature: signature
        )
    }

    var body: Data {
        var w = ByteWriter()
        w.u8(Ticket.version)
        w.u8(Ticket.suiteClassical)
        w.bytes(identityKey)
        w.bytes(staticKey)
        w.bytes(ephemeralKey)
        w.u64(expiry)
        w.u8(UInt8(endpoints.count))
        for e in endpoints {
            w.u8(e.kind.rawValue)
            w.bytes(e.address)
            w.u16(e.port)
        }
        return w.data
    }

    public func encoded() -> Data { body + signature }

    public static func decode(_ data: Data, now: UInt64) throws -> Ticket {
        var r = ByteReader(data)
        guard try r.u8() == version else { throw DollyError.badVersion }
        guard try r.u8() == suiteClassical else { throw DollyError.badSuite }
        let identityKey = try r.bytes(32)
        let staticKey = try r.bytes(32)
        let ephemeralKey = try r.bytes(32)
        let expiry = try r.u64()
        let count = Int(try r.u8())
        guard count <= maxEndpoints else { throw DollyError.badEndpoint }
        var endpoints: [Endpoint] = []
        for _ in 0..<count {
            guard let kind = Endpoint.Kind(rawValue: try r.u8()) else { throw DollyError.badEndpoint }
            let address = try r.bytes(kind == .v4 ? 4 : 16)
            endpoints.append(try Endpoint(kind: kind, address: address, port: try r.u16()))
        }
        let bodyLength = r.offset
        let signature = try r.bytes(64)
        guard r.remaining == 0 else { throw DollyError.malformedPacket }

        let ticket = Ticket(
            identityKey: identityKey, staticKey: staticKey, ephemeralKey: ephemeralKey,
            expiry: expiry, endpoints: endpoints, signature: signature
        )
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: identityKey),
              pub.isValidSignature(signature, for: signatureDomain + data.prefix(bodyLength))
        else { throw DollyError.badSignature }
        guard expiry > now else { throw DollyError.expired }
        return ticket
    }
}
