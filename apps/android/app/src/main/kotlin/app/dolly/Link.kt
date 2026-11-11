package app.dolly

import com.dolly.core.Connection
import com.dolly.core.Crypto
import com.dolly.core.DollyError
import com.dolly.core.DollyException
import com.dolly.core.Endpoint
import com.dolly.core.Identity
import com.dolly.core.KeyPair25519
import com.dolly.core.Session
import com.dolly.core.Stun
import com.dolly.core.StunClient
import com.dolly.core.Ticket
import com.dolly.core.UdpSocket
import com.dolly.core.monotonicMillis
import com.dolly.core.pump
import java.net.SocketException
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext

sealed interface LinkEvent {
    data object Connected : LinkEvent
    class Received(val text: String) : LinkEvent
    class Ended(val reason: LinkEnd) : LinkEvent
}

enum class LinkEnd(val explanation: String) {
    PunchTimeout(
        "Could not connect. Both phones must be open and hold each other's link within a minute. " +
            "A strict firewall or a mobile carrier network may be blocking direct connections.",
    ),
    PeerUnreachable("Your contact stopped responding: they went offline, or their network changed."),
    Idle("The connection went silent."),
    Stopped("You left the conversation."),
}

enum class LinkProblem(val text: String) {
    Network("No network connection, or UDP is blocked on this network."),
    InvalidTicket("That does not look like a Dolly link. Copy the whole link and try again."),
    ExpiredTicket("That link has expired. Ask your contact for a fresh one."),
    OwnTicket("That is your own link. Send it to your contact and paste theirs here."),
    WrongPerson("That link is from someone else, not the contact you chose."),
}

class LinkException(val problem: LinkProblem) : Exception(problem.text)

/**
 * One network session with one peer: finds this phone's public address, makes a signed link (ticket) to hand
 * over, then hole-punches and exchanges messages once the peer's link arrives. The socket, session and
 * connection are touched only by [open] and by the session thread, so the class is safe to share.
 */
class Link private constructor(
    private val identity: Identity,
    private val socket: UdpSocket,
    private val ephemeral: KeyPair25519,
    private val ticket: Ticket,
    val warning: String?,
) {
    val events = Channel<LinkEvent>(Channel.UNLIMITED)
    val ticketText: String = Base64.getEncoder().encodeToString(ticket.encoded())

    private val outbox = ConcurrentLinkedQueue<ByteArray>()
    private val started = AtomicBoolean(false)

    @Volatile
    private var stopRequested = false

    /** Reads the peer's link and starts connecting. Returns the peer's identity key. */
    fun connect(text: String, expecting: ByteArray?): ByteArray {
        val remote = try {
            Ticket.decode(Base64.getMimeDecoder().decode(text.trim()), unixNow())
        } catch (e: IllegalArgumentException) {
            throw LinkException(LinkProblem.InvalidTicket)
        } catch (e: DollyException) {
            throw LinkException(if (e.error == DollyError.Expired) LinkProblem.ExpiredTicket else LinkProblem.InvalidTicket)
        }
        if (expecting != null && !expecting.contentEquals(remote.identityKey)) throw LinkException(LinkProblem.WrongPerson)
        val session = try {
            Session(identity, ephemeral, ticket, remote)
        } catch (e: DollyException) {
            throw LinkException(if (e.error == DollyError.SameIdentity) LinkProblem.OwnTicket else LinkProblem.InvalidTicket)
        }
        if (started.compareAndSet(false, true)) {
            thread(name = "dolly-link", isDaemon = true) { finish(run(session, remote)) }
        }
        return remote.identityKey
    }

    /** Queues a message for the peer. Only call it once connected; the message is not stored anywhere else. */
    fun send(text: String) {
        outbox.add(text.toByteArray())
    }

    fun stop() {
        stopRequested = true
        if (!started.get()) finish(null)
    }

    private fun finish(reason: LinkEnd?) {
        if (reason != null) events.trySend(LinkEvent.Ended(reason))
        events.close()
        socket.close()
    }

    private fun run(session: Session, remote: Ticket): LinkEnd {
        fun newConnection() = Connection(session, remote.endpoints, monotonicMillis())
        var connection = newConnection()
        var attempts = 1
        var established = false

        while (true) {
            for (message in connection.pump(socket, 20)) events.trySend(LinkEvent.Received(String(message, Charsets.UTF_8)))
            if (stopRequested) return LinkEnd.Stopped
            while (true) {
                val message = outbox.poll() ?: break
                runCatching { connection.send(message) }
            }

            when (connection.state) {
                Connection.State.Punching -> Unit
                Connection.State.Established -> if (!established) {
                    established = true
                    events.trySend(LinkEvent.Connected)
                }
                Connection.State.Failed -> when (connection.failReason) {
                    Connection.FailReason.PunchTimeout ->
                        if (!established && attempts < MAX_ATTEMPTS) {
                            attempts++
                            connection = newConnection()
                        } else {
                            return LinkEnd.PunchTimeout
                        }
                    Connection.FailReason.PeerUnreachable -> return LinkEnd.PeerUnreachable
                    else -> return LinkEnd.Idle
                }
            }
        }
    }

    companion object {
        private const val MAX_ATTEMPTS = 6  // a punch attempt lasts 15 s, so we wait about 90 s for the peer's side

        private fun unixNow() = System.currentTimeMillis() / 1000

        /** Asks STUN servers for this phone's public address (takes up to a few seconds) and builds the link. */
        suspend fun open(identity: Identity): Link = withContext(Dispatchers.IO) {
            val socket = try {
                UdpSocket()
            } catch (e: SocketException) {
                throw LinkException(LinkProblem.Network)
            }
            val candidates = ArrayList<Endpoint>()
            fun offer(endpoint: Endpoint) {
                if (candidates.size < Ticket.MAX_ENDPOINTS && endpoint !in candidates) candidates.add(endpoint)
            }
            val servers = UdpSocket.resolve("stun.l.google.com", 19302) + UdpSocket.resolve("stun.cloudflare.com", 3478)
            val found = StunClient.discover(socket, servers)
            found.forEach { offer(it.mapped) }
            UdpSocket.localAddresses(socket.localPort).forEach(::offer)
            if (candidates.isEmpty()) {
                socket.close()
                throw LinkException(LinkProblem.Network)
            }

            val ephemeral = Crypto.x25519Generate()
            val ticket = Ticket.create(identity, ephemeral.publicKey, candidates, unixNow() + 15 * 60)
            val warning = when (Stun.mappingBehavior(found.map { it.mapped })) {
                Stun.MappingBehavior.Symmetric ->
                    "Your network gives a different public port per destination, so a direct connection will probably fail."
                Stun.MappingBehavior.Unknown ->
                    if (found.isEmpty()) "No answer from the address servers: you may be offline or UDP is blocked." else null
                Stun.MappingBehavior.EndpointIndependent -> null
            }
            Link(identity, socket, ephemeral, ticket, warning)
        }
    }
}
