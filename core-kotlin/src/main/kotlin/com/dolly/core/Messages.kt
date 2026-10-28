package com.dolly.core

/**
 * Application messages carried inside encrypted session payloads.
 *
 * ```
 * hello : 0x00
 * chunk : 0x01 | messageId(4) | index(2) | count(2) | data   (data <= 1013 bytes)
 * ```
 */
internal object AppMessage {
    const val HELLO = 0
    const val CHUNK = 1
    const val CHUNK_HEADER_LENGTH = 9
    const val MAX_CHUNKS = 1024
    val maxChunkData: Int get() = Session.MAX_PAYLOAD - CHUNK_HEADER_LENGTH

    /** About 1 MiB. Larger transfers belong to a future file-transfer layer. */
    val maxMessageSize: Int get() = MAX_CHUNKS * maxChunkData

    fun encodeChunks(message: ByteArray, id: Long): List<ByteArray> {
        val count = maxOf(1, (message.size + maxChunkData - 1) / maxChunkData)
        if (count > MAX_CHUNKS) throw DollyException(DollyError.MessageTooLarge)
        return List(count) { index ->
            val start = index * maxChunkData
            val end = minOf(start + maxChunkData, message.size)
            ByteWriter().apply {
                u8(CHUNK)
                u32(id)
                u16(index)
                u16(count)
                bytes(message.copyOfRange(start, end))
            }.toByteArray()
        }
    }
}

/** Puts chunks back together, in any arrival order, within fixed memory bounds. */
internal class Reassembler {
    companion object {
        const val MAX_PARTIAL_MESSAGES = 16
        const val MAX_BUFFERED_BYTES = 4 * 1024 * 1024
    }

    private class Partial(val count: Int) {
        val chunks = HashMap<Int, ByteArray>()
    }

    private val partials = LinkedHashMap<Long, Partial>()  // insertion order = arrival order
    private var bufferedBytes = 0

    /** [chunk] is the payload after the leading type byte. Returns the whole message when complete. */
    fun add(chunk: ByteArray): ByteArray? {
        val r = ByteReader(chunk)
        val id = r.u32()
        val index = r.u16()
        val count = r.u16()
        val data = r.bytes(r.remaining)
        if (count !in 1..AppMessage.MAX_CHUNKS || index >= count || data.size > AppMessage.maxChunkData) {
            throw DollyException(DollyError.MalformedPacket)
        }

        val existing = partials[id]
        val partial: Partial
        if (existing != null) {
            if (existing.count != count) throw DollyException(DollyError.MalformedPacket)
            partial = existing
        } else {
            if (partials.size >= MAX_PARTIAL_MESSAGES) discard(partials.keys.first())
            partial = Partial(count)
            partials[id] = partial
        }
        if (partial.chunks.containsKey(index)) return null  // duplicate chunk
        if (bufferedBytes + data.size > MAX_BUFFERED_BYTES) throw DollyException(DollyError.MalformedPacket)

        partial.chunks[index] = data
        bufferedBytes += data.size
        if (partial.chunks.size != partial.count) return null

        val message = java.io.ByteArrayOutputStream()
        for (i in 0 until partial.count) message.write(partial.chunks.getValue(i))
        discard(id)
        return message.toByteArray()
    }

    private fun discard(id: Long) {
        val partial = partials.remove(id) ?: return
        bufferedBytes -= partial.chunks.values.sumOf { it.size }
    }
}
