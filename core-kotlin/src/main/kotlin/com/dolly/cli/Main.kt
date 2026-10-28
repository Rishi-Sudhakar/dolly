package com.dolly.cli

import com.dolly.core.Connection
import com.dolly.core.Crypto
import com.dolly.core.DollyError
import com.dolly.core.DollyException
import com.dolly.core.Endpoint
import com.dolly.core.Identity
import com.dolly.core.Session
import com.dolly.core.Stun
import com.dolly.core.StunClient
import com.dolly.core.Ticket
import com.dolly.core.UdpSocket
import com.dolly.core.monotonicMillis
import com.dolly.core.pump
import com.dolly.core.toHex
import java.io.File
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.system.exitProcess

private const val HELP = """dolly: serverless end-to-end encrypted chat in your terminal

usage: dolly [options]

  Run it on two machines. Each prints a ticket; paste the other's ticket into each side.
  Both sides must do this within about 15 seconds of each other, and keep the program running.
  Compare the fingerprints over a call or in person to be sure you reached the right person.

options:
  --loopback           do not use STUN; connect over 127.0.0.1 (testing on one machine)
  --send TEXT          queue a message as soon as possible (repeatable)
  --exit-after N       exit successfully after receiving N messages
  --ticket-out FILE    also write your ticket to FILE (for scripts)
  --ticket-in FILE     read the peer's ticket from FILE instead of stdin (waits for it to appear)
  -h, --help           show this help

in chat: type a message and press Enter. /quit leaves."""

private class Options {
    var loopback = false
    val sends = ArrayList<String>()
    var exitAfter: Int? = null
    var ticketOut: String? = null
    var ticketIn: String? = null
}

private fun fail(message: String): Nothing {
    System.err.println(message)
    exitProcess(1)
}

private fun parseOptions(args: Array<String>): Options {
    val options = Options()
    var i = 0
    fun value(flag: String): String {
        i++
        if (i >= args.size) fail("$flag needs a value (see --help)")
        return args[i]
    }
    while (i < args.size) {
        when (val argument = args[i]) {
            "--loopback" -> options.loopback = true
            "--send" -> options.sends.add(value(argument))
            "--exit-after" -> options.exitAfter = value(argument).toIntOrNull()?.takeIf { it > 0 }
                ?: fail("--exit-after needs a positive number")
            "--ticket-out" -> options.ticketOut = value(argument)
            "--ticket-in" -> options.ticketIn = value(argument)
            "-h", "--help" -> {
                println(HELP)
                exitProcess(0)
            }
            else -> fail("unknown option $argument (see --help)")
        }
        i++
    }
    return options
}

/** Short, human-comparable digest of an identity key: "a1b2 c3d4 e5f6 0718 293a". */
private fun fingerprint(identityKey: ByteArray): String =
    Crypto.sha256(identityKey).copyOf(10).toHex().chunked(4).joinToString(" ")

private fun unixNow(): Long = System.currentTimeMillis() / 1000

private fun waitForFile(path: String, timeoutSeconds: Int): String {
    repeat(timeoutSeconds * 5) {
        val file = File(path)
        if (file.exists()) {
            val text = file.readText().trim()
            if (text.isNotEmpty()) return text
        }
        Thread.sleep(200)
    }
    fail("timed out waiting for the peer's ticket in $path")
}

fun main(args: Array<String>) {
    val options = parseOptions(args)
    val socket = try {
        UdpSocket()
    } catch (e: Exception) {
        fail("could not open a UDP socket: ${e.message}")
    }

    // 1. Where can the peer reach us?
    val candidates = ArrayList<Endpoint>()
    fun offer(endpoint: Endpoint) {
        if (candidates.size < 8 && endpoint !in candidates) candidates.add(endpoint)
    }
    if (options.loopback) {
        offer(Endpoint(Endpoint.Kind.V4, byteArrayOf(127, 0, 0, 1), socket.localPort))
    } else {
        println("Asking STUN servers for your public address...")
        val servers = UdpSocket.resolve("stun.l.google.com", 19302) + UdpSocket.resolve("stun.cloudflare.com", 3478)
        val results = StunClient.discover(socket, servers)
        results.forEach { offer(it.mapped) }
        when (Stun.mappingBehavior(results.map { it.mapped })) {
            Stun.MappingBehavior.EndpointIndependent -> println("Your network should allow a direct connection.")
            Stun.MappingBehavior.Symmetric ->
                println("WARNING: your network gives a different public port per destination. A direct connection will probably fail.")
            Stun.MappingBehavior.Unknown -> println(
                if (results.isEmpty()) "WARNING: no STUN answer (offline or UDP blocked). Only your local network address is offered."
                else "Only one STUN server answered, so the network type is unknown.",
            )
        }
        for (address in UdpSocket.localIPv4Addresses()) offer(Endpoint(Endpoint.Kind.V4, address, socket.localPort))
    }
    if (candidates.isEmpty()) fail("no usable network address found")

    // 2. Ticket exchange.
    val identity = Identity.generate()
    val ephemeral = Crypto.x25519Generate()
    val ticket = Ticket.create(identity, ephemeral.publicKey, candidates, unixNow() + 15 * 60)
    val myTicket = Base64.getEncoder().encodeToString(ticket.encoded())
    println("\nYour key fingerprint: ${fingerprint(ticket.identityKey)}")
    println("Reachable at: ${candidates.joinToString(", ")}")
    println("\nYour ticket (give it to your peer):\n$myTicket\n")
    options.ticketOut?.let { path ->
        val temporary = File("$path.tmp")
        temporary.writeText(myTicket)
        java.nio.file.Files.move(
            temporary.toPath(), File(path).toPath(),
            java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
        )
    }

    val theirText = options.ticketIn?.let { waitForFile(it, 120) } ?: run {
        println("Paste your peer's ticket, then press Enter:")
        readLine() ?: fail("no ticket given")
    }
    val theirBytes = try {
        Base64.getDecoder().decode(theirText.trim())
    } catch (e: IllegalArgumentException) {
        fail("that does not look like a ticket (not valid base64)")
    }
    val remote = try {
        Ticket.decode(theirBytes, unixNow())
    } catch (e: DollyException) {
        if (e.error == DollyError.Expired) fail("that ticket has expired; ask your peer for a fresh one")
        fail("that ticket is not valid (${e.error})")
    }
    println("Peer key fingerprint: ${fingerprint(remote.identityKey)}  <- compare with them out of band")
    println("Peer is reachable at: ${remote.endpoints.joinToString(", ")}")

    // 3. Connect and chat.
    val session = Session(identity, ephemeral, ticket, remote)
    val maxAttempts = 6  // a punch attempt lasts 15 s, so we wait about 90 s for the peer to paste their side
    var attempts = 1
    var connection = Connection(session, remote.endpoints, monotonicMillis())
    val beforeConnect = ArrayList<ByteArray>()  // survive a restart of the punching phase
    var announced = false
    var received = 0
    var lingerUntil: Long? = null

    fun queue(text: String) {
        val message = text.toByteArray()
        try {
            connection.send(message)
        } catch (e: DollyException) {
            println("(could not send: ${e.error})")
        }
        if (!announced) beforeConnect.add(message)
    }

    options.sends.forEach(::queue)
    val inbox = ConcurrentLinkedQueue<String>()
    Thread {
        while (true) inbox.add(readLine() ?: break)
    }.apply { isDaemon = true }.start()
    println("Connecting... (type a message and press Enter; /quit leaves)")

    while (true) {
        for (message in connection.pump(socket, 20)) {
            received++
            println("peer> " + String(message, Charsets.UTF_8))
        }
        while (true) {
            val line = inbox.poll() ?: break
            if (line == "/quit") exitProcess(0)
            if (line.isNotEmpty()) queue(line)
        }

        when (connection.state) {
            Connection.State.Punching -> Unit
            Connection.State.Established -> if (!announced) {
                announced = true
                beforeConnect.clear()
                println("Connected to ${connection.peerEndpoint ?: "peer"}. Messages are end-to-end encrypted.")
            }
            Connection.State.Failed -> {
                val reason = connection.failReason
                if (reason == Connection.FailReason.PunchTimeout && !announced && attempts < maxAttempts) {
                    attempts++
                    println("Still trying to reach your peer... ($attempts/$maxAttempts)")
                    connection = Connection(session, remote.endpoints, monotonicMillis())
                    for (message in beforeConnect) runCatching { connection.send(message) }
                } else {
                    println(
                        when (reason) {
                            Connection.FailReason.PunchTimeout ->
                                "Could not connect. Both sides must be running and paste each other's ticket within a minute or so. " +
                                    "If you are on different networks, a firewall or mobile carrier NAT may be blocking direct connections."
                            Connection.FailReason.PeerUnreachable -> "Your peer stopped responding: offline, or their network changed."
                            else -> "The connection went silent."
                        },
                    )
                    exitProcess(1)
                }
            }
        }

        val limit = options.exitAfter
        // Stay a moment so our own messages and acknowledgements still get through.
        if (limit != null && received >= limit && lingerUntil == null) lingerUntil = monotonicMillis() + 2000
        lingerUntil?.let { if (monotonicMillis() >= it) exitProcess(0) }
    }
}
