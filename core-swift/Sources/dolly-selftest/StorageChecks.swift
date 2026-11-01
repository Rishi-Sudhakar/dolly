import Foundation
@testable import DollyCore

private func temporaryDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("dolly-store-" + UUID().uuidString)
}

private func message(_ n: UInt8, outgoing: Bool, _ text: String) -> Message {
    Message(id: Data(repeating: n, count: 16), at: 1_700_000_000_000 + UInt64(n), outgoing: outgoing, text: text)
}

/// Splits a chat log the way the store does, so tests can damage it precisely.
private func records(of log: Data) -> [Data] {
    var out: [Data] = []
    var offset = 0
    while offset + 4 <= log.count {
        let length = log[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
        out.append(log.subdata(in: offset..<offset + 4 + length))
        offset += 4 + length
    }
    return out
}

func runStorageChecks() {
    let contact = Data(repeating: 0xC1, count: 32)

    test("storage: identity survives a restart and is not stored in the clear") {
        let directory = temporaryDirectory(), master = Store.newMasterKey()
        let first = try Store(directory: directory, masterKey: master).identity()
        let second = try Store(directory: directory, masterKey: master).identity()
        expect(first.signing.publicKey.rawRepresentation == second.signing.publicKey.rawRepresentation)
        expect(first.agreement.publicKey.rawRepresentation == second.agreement.publicKey.rawRepresentation)
        let file = try Data(contentsOf: directory.appendingPathComponent("identity"))
        expect(file.range(of: first.signing.rawRepresentation) == nil, "signing seed must not appear on disk")
        expect(file.range(of: first.agreement.rawRepresentation) == nil, "agreement seed must not appear on disk")
    }

    test("storage: a wrong or malformed master key is refused") {
        let directory = temporaryDirectory()
        _ = try Store(directory: directory, masterKey: Store.newMasterKey()).identity()
        expectThrows(.authenticationFailed) { try Store(directory: directory, masterKey: Store.newMasterKey()).identity() }
        expectThrows(.invalidKey) { try Store(directory: directory, masterKey: Data(count: 31)) }
    }

    test("storage: contacts round-trip, and saving again replaces by identity key") {
        let directory = temporaryDirectory(), master = Store.newMasterKey()
        let store = try Store(directory: directory, masterKey: master)
        expect(try store.contacts().isEmpty)
        let ana = Contact(identityKey: contact, name: "Ana Ñandú 🙂", addedAt: 5)
        let raj = Contact(identityKey: Data(repeating: 0xC2, count: 32), name: "Raj", verified: true, addedAt: 6)
        try store.save(ana)
        try store.save(raj)
        var renamed = ana
        renamed.name = "Ana"
        renamed.verified = true
        try store.save(renamed)
        expect(try Store(directory: directory, masterKey: master).contacts() == [raj, renamed])
    }

    test("storage: conversations keep order and delivery receipts across a restart") {
        let directory = temporaryDirectory(), master = Store.newMasterKey()
        let store = try Store(directory: directory, masterKey: master)
        let hello = message(1, outgoing: true, "hello"), reply = message(2, outgoing: false, "héllo back")
        try store.append(hello, with: contact)
        try store.append(reply, with: contact)
        try store.markDelivered(hello.id, with: contact)
        try store.append(message(3, outgoing: true, "later"), with: contact)

        var delivered = hello
        delivered.delivered = true
        let reopened = try Store(directory: directory, masterKey: master)
        expect(try reopened.messages(with: contact) == [delivered, reply, message(3, outgoing: true, "later")])
        expect(try reopened.messages(with: Data(repeating: 0xC9, count: 32)).isEmpty, "other conversations are separate")
        let log = try Data(contentsOf: directory.appendingPathComponent("chat-" + contact.hex))
        expect(log.range(of: Data("héllo back".utf8)) == nil, "message text must not appear on disk")
    }

    test("storage: tampering, swapped records and a wrong key are all detected") {
        let directory = temporaryDirectory(), master = Store.newMasterKey()
        let store = try Store(directory: directory, masterKey: master)
        for n in 1...3 { try store.append(message(UInt8(n), outgoing: true, "m\(n)"), with: contact) }
        let path = directory.appendingPathComponent("chat-" + contact.hex)
        let original = try Data(contentsOf: path)

        var flipped = original
        flipped[flipped.count - 1] ^= 1
        try flipped.write(to: path)
        expectThrows(.authenticationFailed) { try Store(directory: directory, masterKey: master).messages(with: contact) }

        let parts = records(of: original)
        try (parts[1] + parts[0] + parts[2]).write(to: path)
        expectThrows(.authenticationFailed) { try Store(directory: directory, masterKey: master).messages(with: contact) }

        try original.write(to: path)
        expectThrows(.authenticationFailed) {
            try Store(directory: directory, masterKey: Store.newMasterKey()).messages(with: contact)
        }
        expect(try Store(directory: directory, masterKey: master).messages(with: contact).count == 3)
    }

    test("storage: a torn final record is dropped and the log keeps working") {
        let directory = temporaryDirectory(), master = Store.newMasterKey()
        let store = try Store(directory: directory, masterKey: master)
        for n in 1...2 { try store.append(message(UInt8(n), outgoing: true, "m\(n)"), with: contact) }
        let path = directory.appendingPathComponent("chat-" + contact.hex)
        let whole = try Data(contentsOf: path)
        try whole.dropLast(10).write(to: path)  // crash in the middle of the second append

        let restarted = try Store(directory: directory, masterKey: master)
        expect(try restarted.messages(with: contact).map(\.text) == ["m1"])
        try restarted.append(message(3, outgoing: true, "m3"), with: contact)
        expect(try Store(directory: directory, masterKey: master).messages(with: contact).map(\.text) == ["m1", "m3"])
    }
}
