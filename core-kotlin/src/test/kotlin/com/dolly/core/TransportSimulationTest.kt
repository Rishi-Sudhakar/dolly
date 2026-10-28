package com.dolly.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Two connections joined by a lossy, reordering, duplicating link on virtual time. */
class TransportSimulationTest {
    private val simA = Endpoint(Endpoint.Kind.V4, byteArrayOf(198.toByte(), 51, 100, 1), 5000)
    private val simB = Endpoint(Endpoint.Kind.V4, byteArrayOf(203.toByte(), 0, 113, 9), 6000)
    private val expiry = 4_102_444_800L

    private class XorShift(var state: Long) {
        fun next(): Long {
            state = state xor (state shl 13)
            state = state xor (state ushr 7)
            state = state xor (state shl 17)
            return state
        }

        fun unit(): Double = ((next() ushr 1) % 1_000_000L) / 1_000_000.0
    }

    private fun randomSessions(): Pair<Session, Session> {
        val ia = Identity.generate()
        val ib = Identity.generate()
        val ea = Crypto.x25519Generate()
        val eb = Crypto.x25519Generate()
        val ta = Ticket.create(ia, ea.publicKey, emptyList(), expiry)
        val tb = Ticket.create(ib, eb.publicKey, emptyList(), expiry)
        return Session(ia, ea, ta, tb) to Session(ib, eb, tb, ta)
    }

    private inner class Sim(var loss: Double, seed: Long) {
        inner class Packet(val at: Long, val toA: Boolean, val from: Endpoint, val bytes: ByteArray)

        val a: Connection
        val b: Connection
        private val rng = XorShift(seed or 1)
        private var inflight = ArrayList<Packet>()
        var t = 0L
        val gotAtA = ArrayList<ByteArray>()
        val gotAtB = ArrayList<ByteArray>()

        init {
            val (sa, sb) = randomSessions()
            a = Connection(sa, listOf(simB), 0)
            b = Connection(sb, listOf(simA), 0)
        }

        private fun transmit(out: List<Connection.Outgoing>, fromA: Boolean) {
            for (packet in out) {
                if (packet.endpoint != (if (fromA) simB else simA)) continue  // a NAT would drop anything else
                if (rng.unit() < loss) continue
                val delay = 20 + (rng.next() ushr 1) % 60  // varying delay reorders packets
                val source = if (fromA) simA else simB
                inflight.add(Packet(t + delay, !fromA, source, packet.bytes))
                if (rng.unit() < 0.05) inflight.add(Packet(t + delay + (rng.next() ushr 1) % 80, !fromA, source, packet.bytes))
            }
        }

        fun step() {
            val ready = inflight.filter { it.at <= t }.sortedBy { it.at }
            inflight = ArrayList(inflight.filter { it.at > t })
            for (packet in ready) {
                if (packet.toA) gotAtA += a.receive(packet.bytes, packet.from, t)
                else gotAtB += b.receive(packet.bytes, packet.from, t)
            }
            transmit(a.poll(t), fromA = true)
            transmit(b.poll(t), fromA = false)
            t += 10
        }
    }

    private fun makeMessage(side: Int, index: Int): ByteArray {
        val sizes = intArrayOf(0, 10, 1013, 1014, 3000, 20000)
        val header = byteArrayOf(side.toByte()) + ByteWriter().apply { u32(index.toLong()) }.toByteArray()
        return header + ByteArray(sizes[index % sizes.size]) { ((index * 7 + side + it) and 0xff).toByte() }
    }

    private fun hexSet(messages: List<ByteArray>) = messages.map { it.toHex() }.toSet()

    private fun exchange(loss: Double, seed: Long, perSide: Int, limitMs: Long): Sim {
        val sim = Sim(loss, seed)
        val fromA = List(perSide) { makeMessage(1, it) }
        val fromB = List(perSide) { makeMessage(2, it) }
        for (i in 0 until perSide) {
            sim.a.send(fromA[i])
            sim.b.send(fromB[i])
        }
        while (sim.t <= limitMs && !(sim.gotAtB.size == perSide && sim.gotAtA.size == perSide)) sim.step()
        val tag = "loss $loss"
        assertEquals(perSide, sim.gotAtB.size, "$tag: messages at B")
        assertEquals(perSide, sim.gotAtA.size, "$tag: messages at A")
        assertEquals(hexSet(fromA), hexSet(sim.gotAtB), "$tag: A -> B content")
        assertEquals(hexSet(fromB), hexSet(sim.gotAtA), "$tag: B -> A content")
        assertEquals(Connection.State.Established, sim.a.state)
        assertEquals(Connection.State.Established, sim.b.state)
        return sim
    }

    @Test
    fun cleanLinkDeliversEverythingExactlyOnce() {
        exchange(0.0, 1, 40, 600_000)
    }

    @Test
    fun twentyPercentLoss() {
        exchange(0.2, 2, 40, 600_000)
    }

    @Test
    fun thirtyPercentLoss() {
        exchange(0.3, 3, 40, 600_000)
    }

    @Test
    fun offlinePeerIsReported() {
        val sim = Sim(0.0, 5)
        sim.a.send("first".toByteArray())
        while (sim.t < 3000) sim.step()
        assertEquals(1, sim.gotAtB.size)
        assertContentEquals("first".toByteArray(), sim.gotAtB[0])

        sim.loss = 1.0  // peer vanishes
        val cut = sim.t
        sim.a.send("into the void".toByteArray())
        while (sim.t < cut + 90_000 && sim.a.state == Connection.State.Established) sim.step()
        assertEquals(Connection.State.Failed, sim.a.state)
        assertEquals(Connection.FailReason.PeerUnreachable, sim.a.failReason)
        assertEquals(DollyError.ConnectionFailed, assertFailsWith<DollyException> { sim.a.send("more".toByteArray()) }.error)
    }

    @Test
    fun punchingGivesUpWhenNothingGetsThrough() {
        val sim = Sim(1.0, 6)
        while (sim.t < 16_000) sim.step()
        assertEquals(Connection.FailReason.PunchTimeout, sim.a.failReason)
        assertEquals(Connection.FailReason.PunchTimeout, sim.b.failReason)
    }

    @Test
    fun forgedDatagramsAndOversizeMessagesAreRefused() {
        val (sa, _) = randomSessions()
        val a = Connection(sa, listOf(simB), 0)
        assertTrue(a.receive(ByteArray(60) { 0xD0.toByte() }, simB, 1).isEmpty())
        assertEquals(Connection.State.Punching, a.state)
        assertEquals(
            DollyError.MessageTooLarge,
            assertFailsWith<DollyException> { a.send(ByteArray(AppMessage.maxMessageSize + 1)) }.error,
        )
    }
}
