import CryptoKit
import Foundation

public struct Contact: Equatable, Sendable {
    public let identityKey: Data  // Ed25519, 32 bytes; a ticket from this person must carry exactly this key
    public var name: String
    public var verified: Bool     // fingerprints compared out of band
    public let addedAt: UInt64    // unix milliseconds

    public init(identityKey: Data, name: String, verified: Bool = false, addedAt: UInt64) {
        self.identityKey = identityKey
        self.name = name
        self.verified = verified
        self.addedAt = addedAt
    }
}

public struct Message: Equatable, Sendable {
    public let id: Data           // 16 random bytes
    public let at: UInt64         // unix milliseconds
    public let outgoing: Bool
    public let text: String
    public var delivered: Bool    // only meaningful for outgoing messages

    public init(id: Data, at: UInt64, outgoing: Bool, text: String, delivered: Bool = false) {
        self.id = id
        self.at = at
        self.outgoing = outgoing
        self.text = text
        self.delivered = delivered
    }
}

/// Everything a device keeps: its identity, its contacts and its message history, encrypted at rest
/// under a 32-byte master key that the platform keeps in hardware (Secure Enclave / Android Keystore).
/// Not thread-safe; call it from one queue or actor. The on-disk format is in docs/STORAGE.md.
public final class Store {
    public static func newMasterKey() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }

    private let directory: URL
    private let master: Data
    private var keys: [String: SymmetricKey] = [:]
    private var logLengths: [String: Int] = [:]  // records per log, learned on first use

    public init(directory: URL, masterKey: Data) throws {
        guard masterKey.count == 32 else { throw DollyError.invalidKey }
        self.directory = directory
        master = masterKey
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    // MARK: Identity and contacts

    /// The device's identity, created on first use.
    public func identity() throws -> Identity {
        if let sealed = try? Data(contentsOf: url("identity")) {
            var r = ByteReader(try open(sealed, name: "identity", ad: Data("identity".utf8)))
            let signingSeed = try r.bytes(32), signingPublic = try r.bytes(32)
            let agreementSeed = try r.bytes(32), agreementPublic = try r.bytes(32)
            let identity = try Identity(signingSeed: signingSeed, agreementSeed: agreementSeed)
            guard identity.signing.publicKey.rawRepresentation == signingPublic,
                  identity.agreement.publicKey.rawRepresentation == agreementPublic
            else { throw DollyError.authenticationFailed }
            return identity
        }
        let identity = Identity()
        var w = ByteWriter()
        w.bytes(identity.signing.rawRepresentation)
        w.bytes(identity.signing.publicKey.rawRepresentation)
        w.bytes(identity.agreement.rawRepresentation)
        w.bytes(identity.agreement.publicKey.rawRepresentation)
        try write(w.data, file: "identity")
        return identity
    }

    public func contacts() throws -> [Contact] {
        guard let sealed = try? Data(contentsOf: url("contacts")) else { return [] }
        var r = ByteReader(try open(sealed, name: "contacts", ad: Data("contacts".utf8)))
        return try (0..<Int(try r.u16())).map { _ in
            let key = try r.bytes(32)
            let name = String(decoding: try r.bytes(Int(try r.u16())), as: UTF8.self)
            let verified = try r.u8() == 1
            return Contact(identityKey: key, name: name, verified: verified, addedAt: try r.u64())
        }
    }

    /// Adds the contact, or replaces the one with the same identity key.
    public func save(_ contact: Contact) throws {
        let all = try contacts().filter { $0.identityKey != contact.identityKey } + [contact]
        var w = ByteWriter()
        w.u16(UInt16(all.count))
        for c in all {
            let name = Data(c.name.utf8.prefix(Int(UInt16.max)))
            w.bytes(c.identityKey)
            w.u16(UInt16(name.count))
            w.bytes(name)
            w.u8(c.verified ? 1 : 0)
            w.u64(c.addedAt)
        }
        try write(w.data, file: "contacts")
    }

    // MARK: Conversations

    public func append(_ message: Message, with contact: Data) throws {
        let text = Data(message.text.utf8)
        var w = ByteWriter()
        w.u8(Store.recordMessage)
        w.bytes(message.id)
        w.u64(message.at)
        w.u8(message.outgoing ? 1 : 0)
        w.u32(UInt32(text.count))
        w.bytes(text)
        try appendRecord(w.data, to: Store.chat(contact))
    }

    public func markDelivered(_ id: Data, with contact: Data) throws {
        var w = ByteWriter()
        w.u8(Store.recordDelivered)
        w.bytes(id)
        try appendRecord(w.data, to: Store.chat(contact))
    }

    /// The conversation in the order it was written, with delivery receipts applied.
    public func messages(with contact: Data) throws -> [Message] {
        let name = Store.chat(contact)
        guard let file = try? Data(contentsOf: url(name)) else { return [] }
        var messages: [Message] = []
        for (index, range) in Store.scan(file).records.enumerated() {
            var r = ByteReader(try open(file.subdata(in: range), name: name, ad: Store.logAD(name, index)))
            switch try r.u8() {
            case Store.recordMessage:
                let id = try r.bytes(16), at = try r.u64(), outgoing = try r.u8() == 1
                let text = String(decoding: try r.bytes(Int(try r.u32())), as: UTF8.self)
                messages.append(Message(id: id, at: at, outgoing: outgoing, text: text))
            case Store.recordDelivered:
                let id = try r.bytes(16)
                if let i = messages.firstIndex(where: { $0.id == id }) { messages[i].delivered = true }
            default:
                throw DollyError.malformedPacket
            }
        }
        return messages
    }

    // MARK: Sealing

    private static let recordMessage: UInt8 = 1
    private static let recordDelivered: UInt8 = 2
    private static let minimumRecord = 12 + 16  // nonce and tag around an empty plaintext

    private static func chat(_ contact: Data) -> String { "chat-" + contact.hex }

    /// Binds a log record to its file and position, so records cannot be moved, swapped or replayed elsewhere.
    private static func logAD(_ name: String, _ index: Int) -> Data {
        var w = ByteWriter()
        w.bytes(Data(name.utf8))
        w.u64(UInt64(index))
        return w.data
    }

    /// Splits a log into its complete records. A torn final record (a crash mid-append) is not part of the result.
    private static func scan(_ log: Data) -> (records: [Range<Int>], valid: Int) {
        var records: [Range<Int>] = []
        var offset = 0
        while log.count - offset >= 4 {
            let length = log[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
            guard length >= minimumRecord, log.count - offset - 4 >= length else { break }
            records.append(offset + 4..<offset + 4 + length)
            offset += 4 + length
        }
        return (records, offset)
    }

    private func url(_ name: String) -> URL { directory.appendingPathComponent(name) }

    private func key(_ name: String) -> SymmetricKey {
        if let cached = keys[name] { return cached }
        let derived = SymmetricKey(data: Session.hkdf(ikm: master, salt: Data(), info: "dolly/v1/store/" + name, length: 32))
        keys[name] = derived
        return derived
    }

    /// nonce(12) || ciphertext || tag(16), with a fresh random nonce.
    private func seal(_ plaintext: Data, name: String, ad: Data) throws -> Data {
        try ChaChaPoly.seal(plaintext, using: key(name), authenticating: ad).combined
    }

    private func open(_ sealed: Data, name: String, ad: Data) throws -> Data {
        do {
            return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: sealed), using: key(name), authenticating: ad)
        } catch {
            throw DollyError.authenticationFailed
        }
    }

    private func write(_ plaintext: Data, file name: String) throws {
        try seal(plaintext, name: name, ad: Data(name.utf8)).write(to: url(name), options: .atomic)
    }

    private func appendRecord(_ plaintext: Data, to name: String) throws {
        let file = url(name)
        if !FileManager.default.fileExists(atPath: file.path) { FileManager.default.createFile(atPath: file.path, contents: nil) }
        let handle = try FileHandle(forUpdating: file)
        defer { try? handle.close() }

        if logLengths[name] == nil {
            let (records, valid) = Store.scan(try handle.readToEnd() ?? Data())
            try handle.truncate(atOffset: UInt64(valid))
            logLengths[name] = records.count
        }
        let index = logLengths[name]!
        let sealed = try seal(plaintext, name: name, ad: Store.logAD(name, index))
        var w = ByteWriter()
        w.u32(UInt32(sealed.count))
        w.bytes(sealed)
        try handle.seekToEnd()
        try handle.write(contentsOf: w.data)
        try handle.synchronize()
        logLengths[name] = index + 1
    }
}
