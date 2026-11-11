import CryptoKit
import DollyCore
import Foundation
import Observation

@MainActor @Observable
final class AppModel {
    enum Phase: Equatable {
        case idle
        case preparing
        case ready       // our link is made, waiting for the peer's
        case connecting
        case connected
        case ended(String)
    }

    static let maxTextBytes = 16 * 1024

    private(set) var phase = Phase.idle
    private(set) var contacts: [Contact] = []
    private(set) var messages: [Message] = []
    private(set) var peer: Contact?
    private(set) var peerFingerprint = ""
    private(set) var myTicket = ""
    private(set) var myFingerprint = ""
    private(set) var networkWarning: String?
    var notice: String?

    private var database: Database?
    private var identity: Identity?
    private var link: Link?
    private var expecting: Contact?
    private var peerKey: Data?

    func start() async {
        do {
            let database = try Database()
            let identity = try await database.identity()
            myFingerprint = Fingerprint.of(identity.signing.publicKey.rawRepresentation)
            contacts = try await database.contacts()
            self.identity = identity
            self.database = database
        } catch {
            notice = "Could not open your encrypted storage: \(error)"
        }
    }

    // MARK: Sessions

    /// Starts a session. With `contact`, only that person's link is accepted.
    func beginPairing(with contact: Contact?) async {
        guard let identity, phase == .idle else { return }
        phase = .preparing
        expecting = contact
        do {
            let link = try await Link.open(identity: identity)
            self.link = link
            myTicket = link.ticketText
            networkWarning = link.warning
            phase = .ready
            Task { for await event in link.events { await handle(event) } }
        } catch {
            phase = .ended(error.localizedDescription)
        }
    }

    func connect(pasted text: String) {
        guard phase == .ready, let link else { return }
        do {
            let key = try link.connect(to: text, expecting: expecting?.identityKey)
            peerKey = key
            peerFingerprint = Fingerprint.of(key)
            notice = nil
            phase = .connecting
        } catch {
            notice = error.localizedDescription
        }
    }

    func send(_ text: String) {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phase == .connected, let peer, let link, let database, !text.isEmpty else { return }
        guard text.utf8.count <= Self.maxTextBytes else {
            notice = "That message is too long."
            return
        }
        let message = Message(id: Self.randomID(), at: Self.now(), outgoing: true, text: text)
        link.send(text)
        messages.append(message)
        Task { await store(message, with: peer, in: database) }
    }

    func endSession() {
        link?.stop()
        link = nil
        phase = .idle
        peer = nil
        peerKey = nil
        messages = []
        myTicket = ""
        networkWarning = nil
        notice = nil
        expecting = nil
    }

    // MARK: Contacts

    func update(_ contact: Contact) async {
        do {
            try await database?.save(contact)
            contacts = contacts.map { $0.identityKey == contact.identityKey ? contact : $0 }
            if peer?.identityKey == contact.identityKey { peer = contact }
        } catch {
            notice = "Could not save the change: \(error)"
        }
    }

    func history(with contact: Contact) async -> [Message] {
        (try? await database?.messages(with: contact.identityKey)) ?? []
    }

    // MARK: Internals

    private func handle(_ event: LinkEvent) async {
        switch event {
        case .connected:
            guard let key = peerKey, let database else { return }
            do {
                let contact = try await contact(for: key, in: database)
                peer = contact
                messages = try await database.messages(with: key)
                phase = .connected
            } catch {
                notice = "Could not open the conversation: \(error)"
                link?.stop()
            }
        case .message(let text):
            guard let peer, let database else { return }
            let message = Message(id: Self.randomID(), at: Self.now(), outgoing: false, text: text)
            messages.append(message)
            await store(message, with: peer, in: database)
        case .ended(let reason):
            phase = .ended(reason.explanation)
        }
    }

    /// The saved contact for this key, or a new one if we have never met.
    private func contact(for key: Data, in database: Database) async throws -> Contact {
        if let known = contacts.first(where: { $0.identityKey == key }) { return known }
        let created = Contact(identityKey: key, name: "Contact " + Fingerprint.of(key).prefix(9), addedAt: Self.now())
        try await database.save(created)
        contacts.append(created)
        return created
    }

    private func store(_ message: Message, with contact: Contact, in database: Database) async {
        do {
            try await database.append(message, with: contact.identityKey)
        } catch {
            notice = "This message could not be saved: \(error)"
        }
    }

    private static func now() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
    private static func randomID() -> Data { Data((0..<16).map { _ in UInt8.random(in: .min ... .max) }) }
}
