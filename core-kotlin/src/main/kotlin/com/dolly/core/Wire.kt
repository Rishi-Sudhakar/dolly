package com.dolly.core

import java.io.ByteArrayOutputStream

enum class DollyError {
    Truncated, BadVersion, BadSuite, BadSignature, Expired, BadEndpoint,
    SameIdentity, NotReadyToSend, MessageTooLarge,
    MalformedPacket, AuthenticationFailed, TooManySkippedKeys,
    BadStunResponse, ConnectionFailed,
}

class DollyException(val error: DollyError) : Exception(error.name)

internal class ByteWriter {
    private val out = ByteArrayOutputStream()
    fun u8(v: Int) = out.write(v and 0xff)
    fun u16(v: Int) { u8(v shr 8); u8(v) }
    fun u32(v: Long) { for (shift in intArrayOf(24, 16, 8, 0)) u8((v shr shift).toInt()) }
    fun u64(v: Long) { for (shift in 56 downTo 0 step 8) u8((v shr shift).toInt()) }
    fun bytes(b: ByteArray) = out.write(b)
    fun toByteArray(): ByteArray = out.toByteArray()
}

internal class ByteReader(private val data: ByteArray) {
    var offset = 0
        private set
    val remaining get() = data.size - offset

    fun bytes(n: Int): ByteArray {
        if (n < 0 || remaining < n) throw DollyException(DollyError.Truncated)
        return data.copyOfRange(offset, offset + n).also { offset += n }
    }

    fun u8(): Int = bytes(1)[0].toInt() and 0xff
    fun u16(): Int = (u8() shl 8) or u8()
    fun u32(): Long = bytes(4).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
    fun u64(): Long = bytes(8).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
}

/** Unsigned lexicographic comparison, matching Swift's `lexicographicallyPrecedes` on bytes. */
internal fun ByteArray.compareUnsigned(other: ByteArray): Int {
    for (i in 0 until minOf(size, other.size)) {
        val diff = (this[i].toInt() and 0xff) - (other[i].toInt() and 0xff)
        if (diff != 0) return diff
    }
    return size - other.size
}
