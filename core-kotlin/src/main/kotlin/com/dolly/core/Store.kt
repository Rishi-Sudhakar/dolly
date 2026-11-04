package com.dolly.core

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom

class Contact(
    val identityKey: ByteArray,  // Ed25519, 32 bytes; a ticket from this person must carry exactly this key
    val name: String,
    val verified: Boolean = false,  // fingerprints compared out of band
    val addedAt: Long,  // unix milliseconds
) {
    override fun equals(other: Any?) = other is Contact && identityKey.contentEquals(other.identityKey) &&
        name == other.name && verified == other.verified && addedAt == other.addedAt

    override fun hashCode() = identityKey.contentHashCode()
}

class Message(
    val id: ByteArray,  // 16 random bytes
    val at: Long,  // unix milliseconds
    val outgoing: Boolean,
    val text: String,
    val delivered: Boolean = false,  // only meaningful for outgoing messages
) {
    override fun equals(other: Any?) = other is Message && id.contentEquals(other.id) && at == other.at &&
        outgoing == other.outgoing && text == other.text && delivered == other.delivered

    override fun hashCode() = id.contentHashCode()
}

/**
 * Everything a device keeps: its identity, its contacts and its message history, encrypted at rest
 * under a 32-byte master key that the platform keeps in hardware (Android Keystore / Secure Enclave).
 * Not thread-safe; call it from one thread or coroutine context. The on-disk format is in docs/STORAGE.md.
 */
class Store(private val directory: File, masterKey: ByteArray) {
    private val master = masterKey.copyOf()
    private val keys = HashMap<String, ByteArray>()
    private val logLengths = HashMap<String, Int>()  // records per log, learned on first use

    init {
        if (masterKey.size != 32) throw DollyException(DollyError.InvalidKey)
        directory.mkdirs()
    }

    // Identity and contacts

    /** The device's identity, created on first use. */
    fun identity(): Identity {
        val file = File(directory, "identity")
        if (file.exists()) {
            val r = ByteReader(open(file.readBytes(), "identity", "identity".toByteArray()))
            return Identity(KeyPair25519(r.bytes(32), r.bytes(32)), KeyPair25519(r.bytes(32), r.bytes(32)))
        }
        val identity = Identity.generate()
        val w = ByteWriter()
        for (part in listOf(identity.signing.seed, identity.signing.publicKey, identity.agreement.seed, identity.agreement.publicKey)) w.bytes(part)
        write(w.toByteArray(), "identity")
        return identity
    }

    fun contacts(): List<Contact> {
        val file = File(directory, "contacts")
        if (!file.exists()) return emptyList()
        val r = ByteReader(open(file.readBytes(), "contacts", "contacts".toByteArray()))
        return List(r.u16()) {
            val key = r.bytes(32)
            val name = String(r.bytes(r.u16()), Charsets.UTF_8)
            val verified = r.u8() == 1
            Contact(key, name, verified, r.u64())
        }
    }

    /** Adds the contact, or replaces the one with the same identity key. */
    fun save(contact: Contact) {
        val all = contacts().filter { !it.identityKey.contentEquals(contact.identityKey) } + contact
        val w = ByteWriter()
        w.u16(all.size)
        for (c in all) {
            val name = c.name.toByteArray().let { if (it.size > 0xFFFF) it.copyOf(0xFFFF) else it }
            w.bytes(c.identityKey)
            w.u16(name.size)
            w.bytes(name)
            w.u8(if (c.verified) 1 else 0)
            w.u64(c.addedAt)
        }
        write(w.toByteArray(), "contacts")
    }

    // Conversations

    fun append(message: Message, contact: ByteArray) {
        val text = message.text.toByteArray()
        val w = ByteWriter()
        w.u8(RECORD_MESSAGE)
        w.bytes(message.id)
        w.u64(message.at)
        w.u8(if (message.outgoing) 1 else 0)
        w.u32(text.size.toLong())
        w.bytes(text)
        appendRecord(w.toByteArray(), chat(contact))
    }

    fun markDelivered(id: ByteArray, contact: ByteArray) {
        val w = ByteWriter()
        w.u8(RECORD_DELIVERED)
        w.bytes(id)
        appendRecord(w.toByteArray(), chat(contact))
    }

    /** The conversation in the order it was written, with delivery receipts applied. */
    fun messages(contact: ByteArray): List<Message> {
        val name = chat(contact)
        val file = File(directory, name)
        if (!file.exists()) return emptyList()
        val log = file.readBytes()
        val messages = ArrayList<Message>()
        scan(log).forEachIndexed { index, span ->
            val r = ByteReader(open(log.copyOfRange(span.start, span.end), name, logAD(name, index)))
            when (r.u8()) {
                RECORD_MESSAGE -> {
                    val id = r.bytes(16)
                    val at = r.u64()
                    val outgoing = r.u8() == 1
                    messages.add(Message(id, at, outgoing, String(r.bytes(r.u32().toInt()), Charsets.UTF_8)))
                }
                RECORD_DELIVERED -> {
                    val id = r.bytes(16)
                    val i = messages.indexOfFirst { it.id.contentEquals(id) }
                    if (i >= 0) messages[i].let { messages[i] = Message(it.id, it.at, it.outgoing, it.text, delivered = true) }
                }
                else -> throw DollyException(DollyError.MalformedPacket)
            }
        }
        return messages
    }

    // Sealing

    private class Span(val start: Int, val end: Int)

    private fun chat(contact: ByteArray) = "chat-" + contact.toHex()

    /** Binds a log record to its file and position, so records cannot be moved, swapped or replayed elsewhere. */
    private fun logAD(name: String, index: Int): ByteArray {
        val w = ByteWriter()
        w.bytes(name.toByteArray())
        w.u64(index.toLong())
        return w.toByteArray()
    }

    /** Splits a log into its complete records. A torn final record (a crash mid-append) is not part of the result. */
    private fun scan(log: ByteArray): List<Span> {
        val spans = ArrayList<Span>()
        var offset = 0
        while (log.size - offset >= 4) {
            val length = (0 until 4).fold(0) { acc, i -> (acc shl 8) or (log[offset + i].toInt() and 0xff) }
            if (length < MINIMUM_RECORD || length > log.size - offset - 4) break
            spans.add(Span(offset + 4, offset + 4 + length))
            offset += 4 + length
        }
        return spans
    }

    private fun key(name: String) = keys.getOrPut(name) { Crypto.hkdf(master, ByteArray(0), "dolly/v1/store/$name", 32) }

    /** nonce(12) || ciphertext || tag(16), with a fresh random nonce. */
    private fun seal(plaintext: ByteArray, name: String, ad: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { RANDOM.nextBytes(it) }
        return nonce + Crypto.seal(key(name), nonce, ad, plaintext)
    }

    private fun open(sealed: ByteArray, name: String, ad: ByteArray): ByteArray {
        if (sealed.size < MINIMUM_RECORD) throw DollyException(DollyError.AuthenticationFailed)
        return Crypto.open(key(name), sealed.copyOf(12), ad, sealed.copyOfRange(12, sealed.size))
    }

    private fun write(plaintext: ByteArray, name: String) {
        val temporary = File(directory, "$name.tmp")
        FileOutputStream(temporary).use {
            it.write(seal(plaintext, name, name.toByteArray()))
            it.fd.sync()
        }
        Files.move(temporary.toPath(), File(directory, name).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    private fun appendRecord(plaintext: ByteArray, name: String) {
        RandomAccessFile(File(directory, name), "rw").use { file ->
            if (name !in logLengths) {
                val existing = ByteArray(file.length().toInt()).also { file.readFully(it) }
                val spans = scan(existing)
                file.setLength(spans.lastOrNull()?.end?.toLong() ?: 0L)
                logLengths[name] = spans.size
            }
            val index = logLengths.getValue(name)
            val sealed = seal(plaintext, name, logAD(name, index))
            val w = ByteWriter()
            w.u32(sealed.size.toLong())
            w.bytes(sealed)
            file.seek(file.length())
            file.write(w.toByteArray())
            file.fd.sync()
            logLengths[name] = index + 1
        }
    }

    companion object {
        fun newMasterKey(): ByteArray = ByteArray(32).also { RANDOM.nextBytes(it) }

        private const val RECORD_MESSAGE = 1
        private const val RECORD_DELIVERED = 2
        private const val MINIMUM_RECORD = 12 + 16  // nonce and tag around an empty plaintext
        private val RANDOM = SecureRandom()
    }
}
