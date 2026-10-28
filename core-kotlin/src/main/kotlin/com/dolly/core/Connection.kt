package com.dolly.core

/**
 * One end of a peer-to-peer conversation: hole punching, reliable delivery and chunking on top of a
 * [Session]. It performs no I/O and reads no clock. Feed it datagrams with [receive], call [poll]
 * regularly, and transmit whatever [poll] returns. All times are monotonic milliseconds.
 */
class Connection(private val session: Session, private val remoteEndpoints: List<Endpoint>, now: Long) {
    enum class State { Punching, Established, Failed }

    enum class FailReason {
        /** No authenticated packet came back from any candidate endpoint. */
        PunchTimeout,
        /** The peer stopped acknowledging data: offline or unreachable. */
        PeerUnreachable,
        IdleTimeout,
    }

    class Outgoing(val endpoint: Endpoint, val bytes: ByteArray)

    companion object {
        const val PUNCH_INTERVAL = 250L
        const val PUNCH_TIMEOUT = 15_000L
        const val KEEPALIVE_INTERVAL = 15_000L
        const val IDLE_TIMEOUT = 60_000L
    }

    var state = State.Punching
        private set
    var failReason: FailReason? = null
        private set
    var peerEndpoint: Endpoint? = null
        private set

    private val channel = ReliableChannel()
    private val reassembler = Reassembler()
    private val appOutbox = ArrayDeque<ByteArray>()
    private var nextMessageId = 0L
    private var helloQueued = false
    private val pendingOut = ArrayList<Outgoing>()

    private val startedAt = now
    private var nextPunchAt = now
    private var lastSend = now
    private var lastRecv = now

    val isEstablished: Boolean get() = state == State.Established

    /**
     * Queues a message of up to about 1 MiB. Delivery needs both peers online; if the peer is
     * unreachable the connection moves to [State.Failed] with [FailReason.PeerUnreachable].
     */
    fun send(message: ByteArray) {
        if (state == State.Failed) throw DollyException(DollyError.ConnectionFailed)
        val chunks = AppMessage.encodeChunks(message, nextMessageId)
        nextMessageId = (nextMessageId + 1) and 0xFFFF_FFFFL
        chunks.forEach { appOutbox.addLast(it) }
    }

    /** Handles one datagram from the network. Returns messages that completed. */
    fun receive(datagram: ByteArray, from: Endpoint, now: Long): List<ByteArray> {
        if (state == State.Failed) return emptyList()
        val incoming = try {
            Frame.decode(datagram, session.transportKey, session.isInitiator)
        } catch (e: DollyException) {
            return emptyList()
        }

        when (incoming) {
            is Frame.Punch -> {
                // Always answer, even when established: the peer may still be punching.
                pendingOut.add(Outgoing(from, encode(Frame.PunchAck(incoming.nonce))))
                if (state == State.Punching) establish(from, now)
                lastRecv = now
            }
            is Frame.PunchAck -> {
                if (state == State.Punching) establish(from, now)
                lastRecv = now
            }
            is Frame.Ack -> {
                channel.onAck(incoming.ackNext, incoming.sack, now)
                if (state == State.Punching) establish(from, now)
                lastRecv = now
            }
            is Frame.Data -> {
                channel.onAck(incoming.ackNext, incoming.sack, now)
                lastRecv = now
                if (channel.hasReceived(incoming.seq)) {
                    channel.ackDue = true  // our earlier ack may have been lost
                    return emptyList()
                }
                if (!channel.canAccept(incoming.seq)) return emptyList()
                val plain = try {
                    session.decrypt(incoming.payload)
                } catch (e: DollyException) {
                    return emptyList()
                }
                channel.markReceived(incoming.seq)
                if (state == State.Punching) {
                    establish(from, now)
                } else if (peerEndpoint != from) {
                    peerEndpoint = from  // peer's NAT mapping changed; only fresh, decrypted data may move us
                }
                return deliver(plain)
            }
        }
        return emptyList()
    }

    /** Datagrams to transmit now. Call at least every ~50 ms. */
    fun poll(now: Long): List<Outgoing> {
        val out = ArrayList(pendingOut)
        pendingOut.clear()

        when (state) {
            State.Failed -> Unit

            State.Punching -> {
                if (now - startedAt >= PUNCH_TIMEOUT) {
                    fail(FailReason.PunchTimeout)
                } else if (now >= nextPunchAt) {
                    nextPunchAt = now + PUNCH_INTERVAL
                    val punch = encode(Frame.Punch(randomNonce()))
                    for (endpoint in remoteEndpoints) out.add(Outgoing(endpoint, punch))
                }
            }

            State.Established -> pollEstablished(now, out)
        }
        return out
    }

    private fun pollEstablished(now: Long, out: MutableList<Outgoing>) {
        val peer = peerEndpoint ?: return
        if (session.isInitiator && !helloQueued) {
            helloQueued = true
            appOutbox.addFirst(byteArrayOf(AppMessage.HELLO.toByte()))  // lets the responder start talking
        }
        while (session.canSend && appOutbox.isNotEmpty()) {
            val next = appOutbox.removeFirst()
            try {
                channel.enqueue(session.encrypt(next))
            } catch (e: DollyException) {
                // Chunks are sized to always fit; nothing sensible to do with a message that cannot be encrypted.
            }
        }

        val due = channel.dueTransmissions(now)
        if (channel.failed) {
            fail(FailReason.PeerUnreachable)
            return
        }
        for (t in due) {
            val frame = Frame.Data(t.seq, channel.ackNext, channel.sack, t.payload)
            out.add(Outgoing(peer, encode(frame)))
        }
        if (due.isNotEmpty()) {
            channel.ackDue = false  // acks ride on data frames
            lastSend = now
        }
        if (channel.ackDue || now - lastSend >= KEEPALIVE_INTERVAL) {
            out.add(Outgoing(peer, encode(Frame.Ack(channel.ackNext, channel.sack))))
            channel.ackDue = false
            lastSend = now
        }
        if (now - lastRecv >= IDLE_TIMEOUT) fail(FailReason.IdleTimeout)
    }

    private fun establish(endpoint: Endpoint, now: Long) {
        state = State.Established
        peerEndpoint = endpoint
        lastSend = now
        lastRecv = now
    }

    private fun fail(reason: FailReason) {
        state = State.Failed
        failReason = reason
    }

    private fun encode(frame: Frame): ByteArray = frame.encoded(session.transportKey, session.isInitiator)

    private fun deliver(plain: ByteArray): List<ByteArray> {
        if (plain.isEmpty() || plain[0].toInt() != AppMessage.CHUNK) return emptyList()
        val message = try {
            reassembler.add(plain.copyOfRange(1, plain.size))
        } catch (e: DollyException) {
            null
        }
        return if (message == null) emptyList() else listOf(message)
    }

    private fun randomNonce(): ByteArray = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
}
