package com.dolly.core

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Replays the conversation recorded by the Swift implementation and demands byte-identical output. */
class VectorTest {
    private val vectors = JSONObject(File("../test-vectors/vectors.json").readText())
    private val now = vectors.getLong("now")

    private class Peer(val identity: Identity, val ephemeral: KeyPair25519, val ratchets: List<KeyPair25519>, val ticketHex: String)

    private fun peer(name: String): Peer {
        val p = vectors.getJSONObject(name)
        val ticket = Ticket.decode(p.getString("ticket").hexToBytes(), now)
        val identity = Identity(
            KeyPair25519(p.getString("signingSeed").hexToBytes(), p.getString("signingPublic").hexToBytes()),
            KeyPair25519(p.getString("agreementSeed").hexToBytes(), ticket.staticKey),
        )
        val ephemeral = KeyPair25519(p.getString("ephemeralSeed").hexToBytes(), ticket.ephemeralKey)
        val seeds = p.getJSONArray("ratchetSeeds")
        val publics = p.getJSONArray("ratchetPublics")
        val ratchets = List(seeds.length()) { KeyPair25519(seeds.getString(it).hexToBytes(), publics.getString(it).hexToBytes()) }
        return Peer(identity, ephemeral, ratchets, p.getString("ticket"))
    }

    /**
     * [reuseKeys] wraps around the fixed key list. Only for tests that discard a failed decrypt:
     * the session rolls back, but the test's key supply does not.
     */
    private fun session(local: Peer, remote: Peer, reuseKeys: Boolean = false): Session {
        var next = 0
        return Session(
            local.identity, local.ephemeral,
            Ticket.decode(local.ticketHex.hexToBytes(), now),
            Ticket.decode(remote.ticketHex.hexToBytes(), now),
            generate = { local.ratchets[if (reuseKeys) next++ % local.ratchets.size else next++] },
        )
    }

    @Test
    fun reproducesSwiftConversation() {
        val alice = peer("alice")
        val bob = peer("bob")
        val sessions = mapOf("alice" to session(alice, bob), "bob" to session(bob, alice))
        sessions.values.forEach { assertEquals(vectors.getString("transportKey"), it.transportKey.toHex(), "transport key differs from Swift") }
        assertTrue(sessions.getValue("alice").isInitiator)
        assertFalse(sessions.getValue("bob").isInitiator)

        val messages = vectors.getJSONArray("messages")
        for (i in 0 until messages.length()) {
            val m = messages.getJSONObject(i)
            val sender = sessions.getValue(m.getString("from"))
            val receiver = sessions.getValue(if (m.getString("from") == "alice") "bob" else "alice")
            val plaintext = m.getString("plaintext").hexToBytes()
            val packet = sender.encrypt(plaintext)
            assertEquals(m.getString("packet"), packet.toHex(), "packet $i differs from Swift")
            assertContentEquals(plaintext, receiver.decrypt(m.getString("packet").hexToBytes()))
        }
    }

    @Test
    fun rejectsTamperedPacket() {
        val alice = peer("alice")
        val bob = peer("bob")
        val a = session(alice, bob)
        val b = session(bob, alice, reuseKeys = true)
        val genuine = a.encrypt("hello".toByteArray())
        val forged = genuine.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(DollyError.AuthenticationFailed, assertFailsWith<DollyException> { b.decrypt(forged) }.error)
        assertContentEquals("hello".toByteArray(), b.decrypt(genuine))
    }

    @Test
    fun rejectsTamperedTicket() {
        val ticket = vectors.getJSONObject("alice").getString("ticket").hexToBytes()
        ticket[40] = (ticket[40].toInt() xor 1).toByte()
        assertEquals(DollyError.BadSignature, assertFailsWith<DollyException> { Ticket.decode(ticket, now) }.error)
    }
}
