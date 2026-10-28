package com.dolly.core

import java.security.MessageDigest

/**
 * One UDP datagram of the transport layer. Every frame carries a 16-byte tag keyed by the
 * handshake-derived transport key, so forged, spoofed or reflected datagrams are dropped before
 * they reach the ratchet.
 *
 * ```
 * 0xD0 | kind(1) | senderIsInitiator(1) | body | tag(16)
 * punch / punchAck : nonce(8)
 * data             : seq(4) | ackNext(4) | sack(4) | payload (an encrypted session packet)
 * ack              : ackNext(4) | sack(4)
 * tag = HMAC-SHA256(transportKey, "dolly/v1/frame" || all bytes before the tag)[0..<16]
 * ```
 * Sequence numbers are u32 values held in a Long.
 */
sealed class Frame {
    class Punch(val nonce: ByteArray) : Frame()
    class PunchAck(val nonce: ByteArray) : Frame()
    class Data(val seq: Long, val ackNext: Long, val sack: Long, val payload: ByteArray) : Frame()
    class Ack(val ackNext: Long, val sack: Long) : Frame()

    fun encoded(key: ByteArray, isInitiator: Boolean): ByteArray {
        val body = ByteWriter()
        val kind: Int
        when (this) {
            is Punch -> { require(nonce.size == 8); kind = KIND_PUNCH; body.bytes(nonce) }
            is PunchAck -> { require(nonce.size == 8); kind = KIND_PUNCH_ACK; body.bytes(nonce) }
            is Data -> {
                kind = KIND_DATA
                body.u32(seq); body.u32(ackNext); body.u32(sack); body.bytes(payload)
            }
            is Ack -> { kind = KIND_ACK; body.u32(ackNext); body.u32(sack) }
        }
        val signed = ByteWriter().apply {
            u8(MAGIC)
            u8(kind)
            u8(if (isInitiator) 1 else 0)
            bytes(body.toByteArray())
        }.toByteArray()
        return signed + tag(key, signed)
    }

    companion object {
        const val MAGIC = 0xD0
        private const val TAG_LENGTH = 16
        private const val KIND_PUNCH = 1
        private const val KIND_PUNCH_ACK = 2
        private const val KIND_DATA = 3
        private const val KIND_ACK = 4
        private val DOMAIN = "dolly/v1/frame".toByteArray()

        /** Verifies the tag, rejects frames that claim our own role (reflection), then parses. */
        fun decode(datagram: ByteArray, key: ByteArray, localIsInitiator: Boolean): Frame {
            if (datagram.size < 3 + TAG_LENGTH) throw DollyException(DollyError.Truncated)
            val signed = datagram.copyOfRange(0, datagram.size - TAG_LENGTH)
            if ((signed[0].toInt() and 0xff) != MAGIC) throw DollyException(DollyError.MalformedPacket)
            val received = datagram.copyOfRange(datagram.size - TAG_LENGTH, datagram.size)
            if (!MessageDigest.isEqual(received, tag(key, signed))) throw DollyException(DollyError.AuthenticationFailed)

            val r = ByteReader(signed)
            r.u8()
            val kind = r.u8()
            val senderRole = r.u8()
            if (senderRole > 1 || (senderRole == 1) == localIsInitiator) throw DollyException(DollyError.MalformedPacket)

            return when (kind) {
                KIND_PUNCH, KIND_PUNCH_ACK -> {
                    val nonce = r.bytes(8)
                    if (r.remaining != 0) throw DollyException(DollyError.MalformedPacket)
                    if (kind == KIND_PUNCH) Punch(nonce) else PunchAck(nonce)
                }
                KIND_DATA -> {
                    val seq = r.u32()
                    val ackNext = r.u32()
                    val sack = r.u32()
                    if (r.remaining == 0) throw DollyException(DollyError.MalformedPacket)
                    Data(seq, ackNext, sack, r.bytes(r.remaining))
                }
                KIND_ACK -> {
                    val ackNext = r.u32()
                    val sack = r.u32()
                    if (r.remaining != 0) throw DollyException(DollyError.MalformedPacket)
                    Ack(ackNext, sack)
                }
                else -> throw DollyException(DollyError.MalformedPacket)
            }
        }

        private fun tag(key: ByteArray, over: ByteArray): ByteArray =
            Crypto.hmac(key, DOMAIN + over).copyOfRange(0, TAG_LENGTH)
    }
}
