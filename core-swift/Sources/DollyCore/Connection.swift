import Foundation

/// One end of a peer-to-peer conversation: hole punching, reliable delivery and chunking on top of a
/// `Session`. It performs no I/O and reads no clock. Feed it datagrams with `receive`, call `poll`
/// regularly, and transmit whatever `poll` returns. All times are monotonic milliseconds.
public final class Connection {
    public enum FailReason: Equatable {
        /// No authenticated packet came back from any candidate endpoint.
        case punchTimeout
        /// The peer stopped acknowledging data: offline or unreachable.
        case peerUnreachable
        case idleTimeout
    }

    public enum State: Equatable {
        case punching
        case established
        case failed(FailReason)
    }

    public struct Outgoing: Equatable {
        public let endpoint: Endpoint
        public let bytes: Data
    }

    static let punchInterval: Int64 = 250
    static let punchTimeout: Int64 = 15_000
    static let keepaliveInterval: Int64 = 15_000
    static let idleTimeout: Int64 = 60_000

    public private(set) var state: State = .punching
    public private(set) var peerEndpoint: Endpoint?

    private let session: Session
    private let remoteEndpoints: [Endpoint]
    private let channel = ReliableChannel()
    private let reassembler = Reassembler()

    private var appOutbox: [Data] = []
    private var nextMessageID: UInt32 = 0
    private var helloQueued = false
    private var pendingOut: [Outgoing] = []

    private let startedAt: Int64
    private var nextPunchAt: Int64
    private var lastSend: Int64
    private var lastRecv: Int64

    public init(session: Session, remoteEndpoints: [Endpoint], now: Int64) {
        self.session = session
        self.remoteEndpoints = remoteEndpoints
        startedAt = now
        nextPunchAt = now
        lastSend = now
        lastRecv = now
    }

    public var isEstablished: Bool { state == .established }

    /// Queues a message of up to about 1 MiB. Delivery needs both peers online; if the peer is
    /// unreachable the connection moves to `.failed(.peerUnreachable)`.
    public func send(_ message: Data) throws {
        if case .failed = state { throw DollyError.connectionFailed }
        let chunks = try AppMessage.encodeChunks(message, id: nextMessageID)
        nextMessageID &+= 1
        appOutbox.append(contentsOf: chunks)
    }

    /// Handles one datagram from the network. Returns messages that completed.
    @discardableResult
    public func receive(_ datagram: Data, from: Endpoint, now: Int64) -> [Data] {
        if case .failed = state { return [] }
        guard let incoming = try? Frame.decode(
            datagram, key: session.transportKey, localIsInitiator: session.isInitiator
        ) else { return [] }

        switch incoming {
        case .punch(let nonce):
            // Always answer, even when established: the peer may still be punching.
            pendingOut.append(Outgoing(endpoint: from, bytes: encode(.punchAck(nonce: nonce))))
            if state == .punching { establish(at: from, now: now) }
            lastRecv = now
            return []

        case .punchAck:
            if state == .punching { establish(at: from, now: now) }
            lastRecv = now
            return []

        case .ack(let ackNext, let sack):
            channel.onAck(ackNext: ackNext, sack: sack, now: now)
            if state == .punching { establish(at: from, now: now) }
            lastRecv = now
            return []

        case .data(let seq, let ackNext, let sack, let payload):
            channel.onAck(ackNext: ackNext, sack: sack, now: now)
            lastRecv = now
            if channel.hasReceived(seq) {
                channel.ackDue = true  // our earlier ack may have been lost
                return []
            }
            guard channel.canAccept(seq), let plain = try? session.decrypt(payload) else { return [] }
            channel.markReceived(seq)
            if state == .punching {
                establish(at: from, now: now)
            } else if peerEndpoint != from {
                peerEndpoint = from  // peer's NAT mapping changed; only fresh, decrypted data may move us
            }
            return deliver(plain)
        }
    }

    /// Datagrams to transmit now. Call at least every ~50 ms.
    public func poll(now: Int64) -> [Outgoing] {
        var out = pendingOut
        pendingOut = []

        switch state {
        case .failed:
            break

        case .punching:
            if now - startedAt >= Connection.punchTimeout {
                state = .failed(.punchTimeout)
            } else if now >= nextPunchAt {
                nextPunchAt = now + Connection.punchInterval
                let punch = encode(.punch(nonce: Connection.randomNonce()))
                for endpoint in remoteEndpoints { out.append(Outgoing(endpoint: endpoint, bytes: punch)) }
            }

        case .established:
            guard let peer = peerEndpoint else { break }
            if session.isInitiator && !helloQueued {
                helloQueued = true
                appOutbox.insert(Data([AppMessage.hello]), at: 0)  // lets the responder start talking
            }
            while session.canSend, !appOutbox.isEmpty {
                let next = appOutbox.removeFirst()
                if let packet = try? session.encrypt(next) { channel.enqueue(packet) }
            }

            let due = channel.dueTransmissions(now: now)
            if channel.failed {
                state = .failed(.peerUnreachable)
                break
            }
            for (seq, payload) in due {
                let frame = Frame.data(seq: seq, ackNext: channel.ackNext, sack: channel.sack, payload: payload)
                out.append(Outgoing(endpoint: peer, bytes: encode(frame)))
            }
            if !due.isEmpty {
                channel.ackDue = false  // acks ride on data frames
                lastSend = now
            }
            if channel.ackDue || now - lastSend >= Connection.keepaliveInterval {
                out.append(Outgoing(endpoint: peer, bytes: encode(.ack(ackNext: channel.ackNext, sack: channel.sack))))
                channel.ackDue = false
                lastSend = now
            }
            if now - lastRecv >= Connection.idleTimeout { state = .failed(.idleTimeout) }
        }
        return out
    }

    // MARK: - Internals

    private func establish(at endpoint: Endpoint, now: Int64) {
        state = .established
        peerEndpoint = endpoint
        lastSend = now
        lastRecv = now
    }

    private func encode(_ frame: Frame) -> Data {
        frame.encoded(key: session.transportKey, isInitiator: session.isInitiator)
    }

    private func deliver(_ plain: Data) -> [Data] {
        guard plain.first == AppMessage.chunk,
              let message = try? reassembler.add(chunk: Data(plain.dropFirst()))
        else { return [] }
        return [message]
    }

    private static func randomNonce() -> Data {
        Data((0..<8).map { _ in UInt8.random(in: 0...255) })
    }
}
