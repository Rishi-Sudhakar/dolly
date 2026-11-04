package com.dolly.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.net.UnknownHostException

fun monotonicMillis(): Long = System.nanoTime() / 1_000_000

/**
 * A plain dual-stack UDP socket (JDK only): the wildcard socket carries IPv6 and IPv4 traffic, and the JDK
 * reports IPv4 senders as IPv4 addresses. The same socket must be used for STUN and for talking to the peer,
 * otherwise the NAT mapping STUN reported is not the one the peer reaches. On Android, call from a
 * background thread.
 */
class UdpSocket(port: Int = 0) : AutoCloseable {
    private val socket = DatagramSocket(port)
    val localPort: Int get() = socket.localPort

    fun send(data: ByteArray, to: Endpoint) {
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
        return packet.data.copyOfRange(packet.offset, packet.offset + packet.length) to endpoint(packet.address, packet.port)
    }

    override fun close() = socket.close()

    companion object {
        /**
         * Addresses of this machine's active network interfaces at [port]: IPv4 (loopback and link-local excluded)
         * and global IPv6 (2000::/3). Candidates for peers on the same LAN, where a router often cannot loop packets
         * back through its public address, and for peers reachable over IPv6 without NAT.
         */
        fun localAddresses(port: Int): List<Endpoint> =
            (NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList())
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.inetAddresses.toList() }
                .filter { if (it is Inet4Address) !it.isLinkLocalAddress else it.address[0].toInt() and 0xE0 == 0x20 }
                .map { endpoint(it, port) }

        /** IPv4 and IPv6 addresses of [host] (DNS lookup). */
        fun resolve(host: String, port: Int): List<Endpoint> = try {
            InetAddress.getAllByName(host).map { endpoint(it, port) }
        } catch (e: UnknownHostException) {
            emptyList()
        }

        private fun endpoint(address: InetAddress, port: Int) =
            Endpoint(if (address is Inet4Address) Endpoint.Kind.V4 else Endpoint.Kind.V6, address.address, port)
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
