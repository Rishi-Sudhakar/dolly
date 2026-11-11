import CryptoKit
import DollyCore
import Foundation

nonisolated enum LinkEvent: Sendable {
    case connected
    case message(String)
    case ended(LinkEnd)
}

nonisolated enum LinkEnd: Sendable {
    case punchTimeout, peerUnreachable, idle, stopped

    var explanation: String {
        switch self {
        case .punchTimeout:
            "Could not connect. Both phones must be open and hold each other's link within a minute. A strict firewall or a mobile carrier network may be blocking direct connections."
        case .peerUnreachable: "Your contact stopped responding: they went offline, or their network changed."
        case .idle: "The connection went silent."
        case .stopped: "You left the conversation."
        }
    }
}

nonisolated enum LinkError: LocalizedError {
    case network, invalidTicket, expiredTicket, ownTicket, wrongPerson

    var errorDescription: String? {
        switch self {
        case .network: "No network connection, or UDP is blocked on this network."
        case .invalidTicket: "That does not look like a Dolly link. Copy the whole link and try again."
        case .expiredTicket: "That link has expired. Ask your contact for a fresh one."
        case .ownTicket: "That is your own link. Send it to your contact and paste theirs here."
        case .wrongPerson: "That link is from someone else, not the contact you chose."
        }
    }
}

/// One network session with one peer: finds this phone's public address, makes a signed link (ticket) to
/// hand over, then hole-punches and exchanges messages once the peer's link arrives. The socket, session and
/// connection are touched only by `open` and by the session thread, so the class is safe to share.
nonisolated final class Link: @unchecked Sendable {
    private struct Handoff: @unchecked Sendable {
        let session: Session
        let remote: Ticket
    }

    private static let maxAttempts = 6  // a punch attempt lasts 15 s, so we wait about 90 s for the peer's side

    let events: AsyncStream<LinkEvent>
    let ticketText: String
    let warning: String?

    private let continuation: AsyncStream<LinkEvent>.Continuation
    private let identity: Identity
    private let ephemeral: Curve25519.KeyAgreement.PrivateKey
    private let ticket: Ticket
    private let socket: UDPSocket

    private let lock = NSLock()
    private var outbox: [Data] = []
    private var started = false
    private var stopRequested = false

    /// Asks STUN servers for this phone's public address (takes up to a few seconds) and builds the link.
    static func open(identity: Identity) async throws -> Link {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try Link(identity: identity) })
            }
        }
    }

    private init(identity: Identity) throws {
        guard let socket = try? UDPSocket() else { throw LinkError.network }
        var candidates: [Endpoint] = []
        func offer(_ endpoint: Endpoint) {
            if candidates.count < 8 && !candidates.contains(endpoint) { candidates.append(endpoint) }
        }
        let servers = UDPSocket.resolve(host: "stun.l.google.com", port: 19302)
            + UDPSocket.resolve(host: "stun.cloudflare.com", port: 3478)
        let found = StunClient.discover(socket: socket, servers: servers)
        found.forEach { offer($0.mapped) }
        UDPSocket.localAddresses(port: socket.localPort).forEach(offer)
        guard !candidates.isEmpty else { throw LinkError.network }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ticket = try Ticket.create(
            identity: identity, ephemeral: ephemeral.publicKey, endpoints: candidates,
            expiry: UInt64(Date().timeIntervalSince1970) + 15 * 60
        )
        let stream = AsyncStream.makeStream(of: LinkEvent.self)

        self.identity = identity
        self.ephemeral = ephemeral
        self.ticket = ticket
        self.socket = socket
        ticketText = ticket.encoded().base64EncodedString()
        events = stream.stream
        continuation = stream.continuation
        warning = switch Stun.mappingBehavior(found.map(\.mapped)) {
        case .symmetric: "Your network gives a different public port per destination, so a direct connection will probably fail."
        case .unknown where found.isEmpty: "No answer from the address servers: you may be offline or UDP is blocked."
        default: nil
        }
    }

    /// Reads the peer's link and starts connecting. Returns the peer's identity key.
    func connect(to text: String, expecting: Data?) throws -> Data {
        guard let raw = Data(base64Encoded: text, options: .ignoreUnknownCharacters) else { throw LinkError.invalidTicket }
        let remote: Ticket
        do {
            remote = try Ticket.decode(raw, now: UInt64(Date().timeIntervalSince1970))
        } catch DollyError.expired {
            throw LinkError.expiredTicket
        } catch {
            throw LinkError.invalidTicket
        }
        if let expecting, expecting != remote.identityKey { throw LinkError.wrongPerson }
        let session: Session
        do {
            session = try Session(identity: identity, ephemeral: ephemeral, localTicket: ticket, remoteTicket: remote)
        } catch DollyError.sameIdentity {
            throw LinkError.ownTicket
        } catch {
            throw LinkError.invalidTicket
        }

        lock.lock()
        let first = !started
        started = true
        lock.unlock()
        guard first else { return remote.identityKey }

        let handoff = Handoff(session: session, remote: remote)
        Thread.detachNewThread { self.run(handoff) }
        return remote.identityKey
    }

    /// Queues a message for the peer. Only call it once connected; the message is not stored anywhere else.
    func send(_ text: String) {
        lock.lock()
        outbox.append(Data(text.utf8))
        lock.unlock()
    }

    func stop() {
        lock.lock()
        stopRequested = true
        let neverStarted = !started
        lock.unlock()
        if neverStarted { continuation.finish() }
    }

    private func takeOutbox() -> (messages: [Data], stop: Bool) {
        lock.lock()
        defer { lock.unlock() }
        let taken = outbox
        outbox = []
        return (taken, stopRequested)
    }

    private func end(_ reason: LinkEnd) {
        continuation.yield(.ended(reason))
        continuation.finish()
    }

    private func run(_ handoff: Handoff) {
        func newConnection() -> Connection {
            Connection(session: handoff.session, remoteEndpoints: handoff.remote.endpoints, now: monotonicMillis())
        }
        var connection = newConnection()
        var attempts = 1
        var established = false

        while true {
            for message in connection.pump(socket: socket, timeoutMs: 20) {
                continuation.yield(.message(String(decoding: message, as: UTF8.self)))
            }
            let (pending, stop) = takeOutbox()
            if stop { return end(.stopped) }
            for message in pending { try? connection.send(message) }

            switch connection.state {
            case .punching:
                break
            case .established:
                if !established {
                    established = true
                    continuation.yield(.connected)
                }
            case .failed(let reason):
                switch reason {
                case .punchTimeout where !established && attempts < Link.maxAttempts:
                    attempts += 1
                    connection = newConnection()
                case .punchTimeout: return end(.punchTimeout)
                case .peerUnreachable: return end(.peerUnreachable)
                case .idleTimeout: return end(.idle)
                }
            }
        }
    }
}
