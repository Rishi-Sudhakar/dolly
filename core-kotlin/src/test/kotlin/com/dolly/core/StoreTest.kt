package com.dolly.core

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StoreTest {
    private val contact = ByteArray(32) { 0xC1.toByte() }

    private fun directory() = File(Files.createTempDirectory("dolly-store").toFile(), "vault")

    private fun message(n: Int, outgoing: Boolean, text: String) =
        Message(ByteArray(16) { n.toByte() }, 1_700_000_000_000 + n, outgoing, text)

    private fun expectError(error: DollyError, body: () -> Unit) = assertEquals(error, assertFailsWith<DollyException> { body() }.error)

    private fun File.contains(bytes: ByteArray): Boolean {
        val haystack = readBytes()
        return (0..haystack.size - bytes.size).any { i -> bytes.indices.all { haystack[i + it] == bytes[it] } }
    }

    /** Splits a chat log the way the store does, so tests can damage it precisely. */
    private fun records(log: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var offset = 0
        while (offset + 4 <= log.size) {
            val length = (0 until 4).fold(0) { acc, i -> (acc shl 8) or (log[offset + i].toInt() and 0xff) }
            out.add(log.copyOfRange(offset, offset + 4 + length))
            offset += 4 + length
        }
        return out
    }

    @Test
    fun identitySurvivesARestartAndIsNotStoredInTheClear() {
        val directory = directory()
        val master = Store.newMasterKey()
        val first = Store(directory, master).identity()
        val second = Store(directory, master).identity()
        assertContentEquals(first.signing.publicKey, second.signing.publicKey)
        assertContentEquals(first.agreement.publicKey, second.agreement.publicKey)
        assertContentEquals(first.signing.seed, second.signing.seed)
        assertTrue(!File(directory, "identity").contains(first.signing.seed), "signing seed must not appear on disk")
        assertTrue(!File(directory, "identity").contains(first.agreement.seed), "agreement seed must not appear on disk")
    }

    @Test
    fun aWrongOrMalformedMasterKeyIsRefused() {
        val directory = directory()
        Store(directory, Store.newMasterKey()).identity()
        expectError(DollyError.AuthenticationFailed) { Store(directory, Store.newMasterKey()).identity() }
        expectError(DollyError.InvalidKey) { Store(directory, ByteArray(31)) }
    }

    @Test
    fun contactsRoundTripAndSavingAgainReplacesByIdentityKey() {
        val directory = directory()
        val master = Store.newMasterKey()
        val store = Store(directory, master)
        assertTrue(store.contacts().isEmpty())
        val ana = Contact(contact, "Ana Ñandú 🙂", addedAt = 5)
        val raj = Contact(ByteArray(32) { 0xC2.toByte() }, "Raj", verified = true, addedAt = 6)
        store.save(ana)
        store.save(raj)
        val renamed = Contact(contact, "Ana", verified = true, addedAt = 5)
        store.save(renamed)
        assertEquals(listOf(raj, renamed), Store(directory, master).contacts())
    }

    @Test
    fun conversationsKeepOrderAndDeliveryReceiptsAcrossARestart() {
        val directory = directory()
        val master = Store.newMasterKey()
        val store = Store(directory, master)
        val hello = message(1, true, "hello")
        val reply = message(2, false, "héllo back")
        store.append(hello, contact)
        store.append(reply, contact)
        store.markDelivered(hello.id, contact)
        store.append(message(3, true, "later"), contact)

        val delivered = Message(hello.id, hello.at, true, "hello", delivered = true)
        val reopened = Store(directory, master)
        assertEquals(listOf(delivered, reply, message(3, true, "later")), reopened.messages(contact))
        assertTrue(reopened.messages(ByteArray(32) { 0xC9.toByte() }).isEmpty(), "other conversations are separate")
        assertTrue(!File(directory, "chat-" + contact.toHex()).contains("héllo back".toByteArray()), "message text must not appear on disk")
    }

    @Test
    fun tamperingSwappedRecordsAndAWrongKeyAreAllDetected() {
        val directory = directory()
        val master = Store.newMasterKey()
        val store = Store(directory, master)
        for (n in 1..3) store.append(message(n, true, "m$n"), contact)
        val path = File(directory, "chat-" + contact.toHex())
        val original = path.readBytes()

        path.writeBytes(original.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
        expectError(DollyError.AuthenticationFailed) { Store(directory, master).messages(contact) }

        val parts = records(original)
        path.writeBytes(parts[1] + parts[0] + parts[2])
        expectError(DollyError.AuthenticationFailed) { Store(directory, master).messages(contact) }

        path.writeBytes(original)
        expectError(DollyError.AuthenticationFailed) { Store(directory, Store.newMasterKey()).messages(contact) }
        assertEquals(3, Store(directory, master).messages(contact).size)
    }

    @Test
    fun aTornFinalRecordIsDroppedAndTheLogKeepsWorking() {
        val directory = directory()
        val master = Store.newMasterKey()
        val store = Store(directory, master)
        for (n in 1..2) store.append(message(n, true, "m$n"), contact)
        val path = File(directory, "chat-" + contact.toHex())
        path.writeBytes(path.readBytes().let { it.copyOf(it.size - 10) })  // crash in the middle of the second append

        val restarted = Store(directory, master)
        assertEquals(listOf("m1"), restarted.messages(contact).map { it.text })
        restarted.append(message(3, true, "m3"), contact)
        assertEquals(listOf("m1", "m3"), Store(directory, master).messages(contact).map { it.text })
    }
}
