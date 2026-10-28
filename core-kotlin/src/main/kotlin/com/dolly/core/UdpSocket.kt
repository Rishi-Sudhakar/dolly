package com.dolly.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.SocketTimeoutException

fun monotonicMillis(): Long = System.nanoTime() / 1_000_000

/**
 * A plain UDP socket (JDK only). The same socket must be used for STUN and for talking to the peer,
 * otherwise the NAT mapping STUN reported is not the one the peer reaches. On Android, call from a
 * background thread.
 */
class UdpSocket(port: Int = 0) : AutoCloseable {
    private val socket = DatagramSocket(port)
    val localPort: Int get() = socket.localPort

    fun send(data: ByteArray, to: Endpoint) {
        if (to.kind != Endpoint.Kind.V4) throw DollyException(DollyError.BadEndpoint)
        socket.send(DatagramPacket(data, data.size, InetAddress.getByAddress(to.address), to.port))
    }

    /** Waits up to [timeoutMs] (at least 1) for one datagram. */
    fun receive(timeoutMs: Int): Pair<ByteArray, Endpoint>? {
        socket.soTimeout = maxOf(timeoutMs, 1)
        val buffer = ByteArray(2048)
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            socket.receive(packet)
        } catch (e: SocketTimeoutException) {
            return null
        }
        val address = packet.address.address
        val kind = if (address.size == 4) Endpoint.Kind.V4 else Endpoint.Kind.V6
        return packet.data.copyOfRange(packet.offset, packet.offset + packet.length) to Endpoint(kind, address, packet.port)
    }

    override fun close() = socket.close()

    companion object {
        /** IPv4 addresses of [host] (DNS lookup). */
        fun resolve(host: String, port: Int): List<Endpoint> = try {
            InetAddress.getAllByName(host).filterIsInstance<Inet4Address>().map { Endpoint(Endpoint.Kind.V4, it.address, port) }
        } catch (e: java.net.UnknownHostException) {
            emptyList()
        }
    }
}

/** One turn of the I/O loop: read what arrived, then transmit whatever is due. Returns completed messages. */
fun Connection.pump(socket: UdpSocket, timeoutMs: Int = 20): List<ByteArray> {
    val messages = ArrayList<ByteArray>()
    var wait = timeoutMs
    while (true) {
        val (datagram, from) = socket.receive(wait) ?: break
        messages += receive(datagram, from, monotonicMillis())
        wait = 1
    }
    for (packet in poll(monotonicMillis())) runCatching { socket.send(packet.bytes, packet.endpoint) }
    return messages
}

class StunResult(val server: Endpoint, val mapped: Endpoint)

object StunClient {
    /** Asks each server for the public address of [socket]. Retries a few times because UDP drops packets. */
    fun discover(socket: UdpSocket, servers: List<Endpoint>, timeoutMs: Long = 2500): List<StunResult> {
        val transactions = LinkedHashMap<String, Pair<ByteArray, Endpoint>>()
        for (server in servers) {
            val id = Stun.newTransactionId()
            transactions[id.toHex()] = id to server
        }
        val results = ArrayList<StunResult>()

        val start = monotonicMillis()
        var lastSend = Long.MIN_VALUE / 2
        while (monotonicMillis() - start < timeoutMs && transactions.isNotEmpty()) {
            if (monotonicMillis() - lastSend >= 500) {
                lastSend = monotonicMillis()
                for ((id, server) in transactions.values) runCatching { socket.send(Stun.bindingRequest(id), server) }
            }
            val (datagram, _) = socket.receive(50) ?: continue
            if (datagram.size < 20) continue
            val key = datagram.copyOfRange(8, 20).toHex()
            val (id, server) = transactions[key] ?: continue
            val mapped = runCatching { Stun.parseBindingResponse(datagram, id) }.getOrNull() ?: continue
            results.add(StunResult(server, mapped))
            transactions.remove(key)
        }
        return results
    }
}
