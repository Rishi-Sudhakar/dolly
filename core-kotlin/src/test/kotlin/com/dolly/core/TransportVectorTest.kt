package com.dolly.core

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Replays frames, chunks and STUN messages produced by the Swift implementation. */
class TransportVectorTest {
    private val vectors = JSONObject(File("../test-vectors/transport.json").readText())
    private val key = vectors.getString("transportKey").hexToBytes()

    @Test
    fun framesMatchSwiftBytes() {
        val frames = vectors.getJSONArray("frames")
        for (i in 0 until frames.length()) {
            val f = frames.getJSONObject(i)
            val senderIsInitiator = f.getBoolean("senderIsInitiator")
            val datagram = f.getString("datagram").hexToBytes()
            val decoded = Frame.decode(datagram, key, localIsInitiator = !senderIsInitiator)

            val rebuilt = when (f.getString("kind")) {
                "punch" -> {
                    assertContentEquals(f.getString("nonce").hexToBytes(), (decoded as Frame.Punch).nonce)
                    Frame.Punch(decoded.nonce)
                }
                "punchAck" -> {
                    assertContentEquals(f.getString("nonce").hexToBytes(), (decoded as Frame.PunchAck).nonce)
                    Frame.PunchAck(decoded.nonce)
                }
                "data" -> {
                    val d = decoded as Frame.Data
                    assertEquals(f.getLong("seq"), d.seq)
                    assertEquals(f.getLong("ackNext"), d.ackNext)
                    assertEquals(f.getLong("sack"), d.sack)
                    assertContentEquals(f.getString("payload").hexToBytes(), d.payload)
                    Frame.Data(d.seq, d.ackNext, d.sack, d.payload)
                }
                "ack" -> {
                    val a = decoded as Frame.Ack
                    assertEquals(f.getLong("ackNext"), a.ackNext)
                    assertEquals(f.getLong("sack"), a.sack)
                    Frame.Ack(a.ackNext, a.sack)
                }
                else -> error("unknown frame kind")
            }
            assertEquals(f.getString("datagram"), rebuilt.encoded(key, senderIsInitiator).toHex(), "frame $i re-encodes differently")

            val tampered = datagram.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
            assertFailsWith<DollyException> { Frame.decode(tampered, key, !senderIsInitiator) }
            assertEquals(
                DollyError.MalformedPacket,
                assertFailsWith<DollyException> { Frame.decode(datagram, key, senderIsInitiator) }.error,
                "a frame claiming our own role must be rejected as a reflection",
            )
        }
    }

    @Test
    fun chunksMatchSwiftBytes() {
        val cases = vectors.getJSONArray("chunks")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val message = c.getString("message").hexToBytes()
            val expected = c.getJSONArray("chunks")
            val chunks = AppMessage.encodeChunks(message, c.getLong("id"))
            assertEquals(expected.length(), chunks.size)
            chunks.forEachIndexed { n, chunk -> assertEquals(expected.getString(n), chunk.toHex(), "chunk $n") }

            val reassembler = Reassembler()
            var result: ByteArray? = null
            for (chunk in chunks.reversed()) result = reassembler.add(chunk.copyOfRange(1, chunk.size)) ?: result
            assertContentEquals(message, result)
        }
    }

    @Test
    fun stunMatchesSwiftBytes() {
        val stun = vectors.getJSONObject("stun")
        val txid = stun.getString("transactionID").hexToBytes()
        assertEquals(stun.getString("request"), Stun.bindingRequest(txid).toHex())

        val responses = stun.getJSONArray("responses")
        for (i in 0 until responses.length()) {
            val r = responses.getJSONObject(i)
            val endpoint = Stun.parseBindingResponse(r.getString("hex").hexToBytes(), txid)
            assertEquals(if (r.getString("kind") == "v4") Endpoint.Kind.V4 else Endpoint.Kind.V6, endpoint.kind)
            assertEquals(r.getString("address"), endpoint.address.toHex())
            assertEquals(r.getInt("port"), endpoint.port)
        }

        val first = responses.getJSONObject(0).getString("hex").hexToBytes()
        assertFailsWith<DollyException> { Stun.parseBindingResponse(first, ByteArray(12)) }
        assertFailsWith<DollyException> { Stun.parseBindingResponse(first.copyOf(first.size - 3), txid) }
        assertFailsWith<DollyException> { Stun.parseBindingResponse(ByteArray(0), txid) }
    }

    @Test
    fun natMappingClassification() {
        val one = Endpoint(Endpoint.Kind.V4, byteArrayOf(1, 2, 3, 4), 1000)
        val two = Endpoint(Endpoint.Kind.V4, byteArrayOf(1, 2, 3, 4), 1001)
        assertEquals(Stun.MappingBehavior.Unknown, Stun.mappingBehavior(listOf(one)))
        assertEquals(Stun.MappingBehavior.EndpointIndependent, Stun.mappingBehavior(listOf(one, one)))
        assertEquals(Stun.MappingBehavior.Symmetric, Stun.mappingBehavior(listOf(one, two)))
        assertTrue(one == Endpoint(Endpoint.Kind.V4, byteArrayOf(1, 2, 3, 4), 1000))
    }
}
