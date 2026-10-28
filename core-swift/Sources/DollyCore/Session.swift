import CryptoKit
import Foundation

/// An established, authenticated channel with one peer: handshake output plus a Double Ratchet.
///
/// The peer with the lexicographically lower identity key is the initiator. The responder can
/// only send after it has received one packet, so the initiator should send a hello on connect.
public final class Session {
    public typealias KeyGenerator = () -> Curve25519.KeyAgreement.PrivateKey

    static let maxSkipped = 1000
    static let buckets = [256, 512, 1024]
    static let headerLength = 40
    static let packetVersion: UInt8 = 1
    static let packetTypeData: UInt8 = 1
    static let tagLength = 16
    /// Largest payload that fits the biggest padding bucket (2 bytes are the length prefix).
    public static let maxPayload = buckets.last! - 2

    private struct SkippedID: Hashable {
        let dh: Data
        let n: UInt32
    }

    private struct State {
        var rootKey: Data
        var dhs: Curve25519.KeyAgreement.PrivateKey
        var dhr: Data?
        var cks: Data?
        var ckr: Data?
        var ns: UInt32 = 0
        var nr: UInt32 = 0
        var pn: UInt32 = 0
        var skipped: [SkippedID: Data] = [:]
        var skippedOrder: [SkippedID] = []
    }

    private var state: State
    private let adPrefix: Data
    private let generate: KeyGenerator
    public let isInitiator: Bool
    public let peerIdentityKey: Data
    /// Authenticates transport datagrams (punches, acks, data). Both peers derive the same key from the handshake.
    public let transportKey: Data

    public var canSend: Bool { state.cks != nil }

    public init(
        identity: Identity,
        ephemeral: Curve25519.KeyAgreement.PrivateKey,
        localTicket: Ticket,
        remoteTicket: Ticket,
        keyGenerator: @escaping KeyGenerator = { Curve25519.KeyAgreement.PrivateKey() }
    ) throws {
        guard localTicket.identityKey != remoteTicket.identityKey else { throw DollyError.sameIdentity }
        let initiator = localTicket.identityKey.lexicographicallyPrecedes(remoteTicket.identityKey)
        let (a, b) = initiator ? (localTicket, remoteTicket) : (remoteTicket, localTicket)

        let remoteStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteTicket.staticKey)
        let remoteEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remoteTicket.ephemeralKey)

        // dh1 = DH(static_A, eph_B), dh2 = DH(eph_A, static_B), dh3 = DH(eph_A, eph_B)
        let dh1 = try initiator
            ? Session.dh(identity.agreement, remoteEphemeral)
            : Session.dh(ephemeral, remoteStatic)
        let dh2 = try initiator
            ? Session.dh(ephemeral, remoteStatic)
            : Session.dh(identity.agreement, remoteEphemeral)
        let dh3 = try Session.dh(ephemeral, remoteEphemeral)

        let transcript = Data(SHA256.hash(data: a.encoded() + b.encoded()))
        let rootKey = Session.hkdf(ikm: dh1 + dh2 + dh3, salt: transcript, info: "dolly/v1/handshake", length: 32)

        transportKey = Session.hkdf(ikm: rootKey, salt: Data(), info: "dolly/v1/transport", length: 32)
        adPrefix = Data("dolly/v1/msg".utf8) + a.identityKey + b.identityKey
        generate = keyGenerator
        isInitiator = initiator
        peerIdentityKey = remoteTicket.identityKey

        if initiator {
            let dhs = keyGenerator()
            let (rk, cks) = Session.kdfRoot(rootKey, try Session.dh(dhs, remoteEphemeral))
            state = State(rootKey: rk, dhs: dhs, dhr: remoteTicket.ephemeralKey, cks: cks)
        } else {
            state = State(rootKey: rootKey, dhs: ephemeral)
        }
    }

    // MARK: - Send

    public func encrypt(_ payload: Data) throws -> Data {
        guard let cks = state.cks else { throw DollyError.notReadyToSend }
        guard payload.count <= Session.maxPayload else { throw DollyError.messageTooLarge }

        let (messageKey, nextChain) = Session.kdfChain(cks)
        var header = ByteWriter()
        header.bytes(state.dhs.publicKey.rawRepresentation)
        header.u32(state.pn)
        header.u32(state.ns)

        let sealed = try Session.seal(Session.pad(payload), messageKey: messageKey, ad: adPrefix + header.data)
        state.cks = nextChain
        state.ns += 1

        var packet = ByteWriter()
        packet.u8(Session.packetVersion)
        packet.u8(Session.packetTypeData)
        packet.bytes(header.data)
        packet.bytes(sealed)
        return packet.data
    }

    // MARK: - Receive

    /// Decrypts a packet. A packet that fails authentication leaves the session state untouched.
    public func decrypt(_ packet: Data) throws -> Data {
        var r = ByteReader(packet)
        guard try r.u8() == Session.packetVersion else { throw DollyError.badVersion }
        guard try r.u8() == Session.packetTypeData else { throw DollyError.malformedPacket }
        let headerBytes = try r.bytes(Session.headerLength)
        var h = ByteReader(headerBytes)
        let dh = try h.bytes(32)
        let pn = try h.u32()
        let n = try h.u32()
        let sealed = try r.bytes(r.remaining)
        guard sealed.count >= Session.tagLength else { throw DollyError.malformedPacket }

        var s = state
        let ad = adPrefix + headerBytes
        let id = SkippedID(dh: dh, n: n)
        let plaintext: Data

        if let key = s.skipped[id] {
            plaintext = try Session.open(sealed, messageKey: key, ad: ad)
            s.skipped[id] = nil
            s.skippedOrder.removeAll { $0 == id }
        } else {
            if s.dhr != dh {
                if s.dhr != nil, s.ckr != nil { try skipKeys(&s, until: pn) }
                try dhRatchet(&s, remote: dh)
            }
            try skipKeys(&s, until: n)
            guard let ckr = s.ckr else { throw DollyError.authenticationFailed }
            let (messageKey, nextChain) = Session.kdfChain(ckr)
            plaintext = try Session.open(sealed, messageKey: messageKey, ad: ad)
            s.ckr = nextChain
            s.nr += 1
        }
        state = s
        return try Session.unpad(plaintext)
    }

    private func skipKeys(_ s: inout State, until: UInt32) throws {
        guard s.nr < until else { return }
        guard Int(until - s.nr) <= Session.maxSkipped, var chain = s.ckr, let dhr = s.dhr else {
            throw DollyError.tooManySkippedKeys
        }
        while s.nr < until {
            let (messageKey, next) = Session.kdfChain(chain)
            let id = SkippedID(dh: dhr, n: s.nr)
            s.skipped[id] = messageKey
            s.skippedOrder.append(id)
            if s.skippedOrder.count > Session.maxSkipped { s.skipped[s.skippedOrder.removeFirst()] = nil }
            chain = next
            s.nr += 1
        }
        s.ckr = chain
    }

    private func dhRatchet(_ s: inout State, remote: Data) throws {
        let remoteKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remote)
        s.pn = s.ns
        s.ns = 0
        s.nr = 0
        s.dhr = remote
        let (rk1, ckr) = Session.kdfRoot(s.rootKey, try Session.dh(s.dhs, remoteKey))
        s.ckr = ckr
        s.dhs = generate()
        let (rk2, cks) = Session.kdfRoot(rk1, try Session.dh(s.dhs, remoteKey))
        s.rootKey = rk2
        s.cks = cks
    }

    // MARK: - Primitives

    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }
    }

    static func hkdf(ikm: Data, salt: Data, info: String, length: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: Data(info.utf8), outputByteCount: length
        )
        return key.withUnsafeBytes { Data($0) }
    }

    static func kdfRoot(_ rootKey: Data, _ dhOut: Data) -> (Data, Data) {
        let out = hkdf(ikm: dhOut, salt: rootKey, info: "dolly/v1/ratchet", length: 64)
        return (out.prefix(32), out.suffix(32))
    }

    static func hmac(_ key: Data, _ byte: UInt8) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data([byte]), using: SymmetricKey(data: key)))
    }

    static func kdfChain(_ chainKey: Data) -> (messageKey: Data, nextChain: Data) {
        (hmac(chainKey, 0x01), hmac(chainKey, 0x02))
    }

    /// Message key -> 32-byte AEAD key + 12-byte nonce. Each message key is used exactly once.
    private static func aeadParams(_ messageKey: Data) -> (SymmetricKey, ChaChaPoly.Nonce) {
        let out = hkdf(ikm: messageKey, salt: Data(), info: "dolly/v1/msg-key", length: 44)
        return (SymmetricKey(data: out.prefix(32)), try! ChaChaPoly.Nonce(data: out.suffix(12)))
    }

    private static func seal(_ plaintext: Data, messageKey: Data, ad: Data) throws -> Data {
        let (key, nonce) = aeadParams(messageKey)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: ad)
        return box.ciphertext + box.tag
    }

    private static func open(_ sealed: Data, messageKey: Data, ad: Data) throws -> Data {
        let (key, nonce) = aeadParams(messageKey)
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: nonce, ciphertext: sealed.dropLast(tagLength), tag: sealed.suffix(tagLength)
            )
            return try ChaChaPoly.open(box, using: key, authenticating: ad)
        } catch {
            throw DollyError.authenticationFailed
        }
    }

    // MARK: - Padding (hides message length within a bucket)

    static func pad(_ payload: Data) -> Data {
        var w = ByteWriter()
        w.u16(UInt16(payload.count))
        w.bytes(payload)
        let target = buckets.first { $0 >= w.data.count }!
        w.bytes(Data(count: target - w.data.count))
        return w.data
    }

    static func unpad(_ padded: Data) throws -> Data {
        var r = ByteReader(padded)
        let length = Int(try r.u16())
        guard length <= r.remaining else { throw DollyError.malformedPacket }
        return try r.bytes(length)
    }
}
