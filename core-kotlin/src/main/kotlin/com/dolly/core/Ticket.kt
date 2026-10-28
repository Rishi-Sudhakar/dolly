package com.dolly.core

/** A device's long-term keys. The Ed25519 key signs tickets; the X25519 key is used in the handshake. */
class Identity(val signing: KeyPair25519, val agreement: KeyPair25519) {
    companion object {
        fun generate() = Identity(Crypto.ed25519Generate(), Crypto.x25519Generate())
    }
}

class Endpoint(val kind: Kind, val address: ByteArray, val port: Int) {
    enum class Kind(val code: Int, val length: Int) { V4(4, 4), V6(6, 16) }

    init {
        if (address.size != kind.length) throw DollyException(DollyError.BadEndpoint)
    }
}

/** Signed, self-contained invitation to connect. Exchanged out of band (QR, RCS text, share sheet). */
class Ticket(
    val identityKey: ByteArray,   // Ed25519, 32 bytes
    val staticKey: ByteArray,     // X25519, 32 bytes
    val ephemeralKey: ByteArray,  // X25519, 32 bytes, single-use
    val expiry: Long,             // unix seconds
    val endpoints: List<Endpoint>,
    val signature: ByteArray,     // Ed25519 over domain || body, 64 bytes
) {
    companion object {
        const val VERSION = 1
        const val SUITE_CLASSICAL = 1
        const val MAX_ENDPOINTS = 8
        private val SIGNATURE_DOMAIN = "dolly/v1/ticket".toByteArray()

        fun create(identity: Identity, ephemeralPublic: ByteArray, endpoints: List<Endpoint>, expiry: Long): Ticket {
            if (endpoints.size > MAX_ENDPOINTS) throw DollyException(DollyError.BadEndpoint)
            val unsigned = Ticket(
                identity.signing.publicKey, identity.agreement.publicKey, ephemeralPublic,
                expiry, endpoints, ByteArray(0),
            )
            val signature = Crypto.sign(identity.signing.seed, SIGNATURE_DOMAIN + unsigned.body())
            return Ticket(unsigned.identityKey, unsigned.staticKey, unsigned.ephemeralKey, expiry, endpoints, signature)
        }

        fun decode(data: ByteArray, now: Long): Ticket {
            val r = ByteReader(data)
            if (r.u8() != VERSION) throw DollyException(DollyError.BadVersion)
            if (r.u8() != SUITE_CLASSICAL) throw DollyException(DollyError.BadSuite)
            val identityKey = r.bytes(32)
            val staticKey = r.bytes(32)
            val ephemeralKey = r.bytes(32)
            val expiry = r.u64()
            val count = r.u8()
            if (count > MAX_ENDPOINTS) throw DollyException(DollyError.BadEndpoint)
            val endpoints = List(count) {
                val kind = Endpoint.Kind.values().firstOrNull { k -> k.code == r.u8() }
                    ?: throw DollyException(DollyError.BadEndpoint)
                Endpoint(kind, r.bytes(kind.length), r.u16())
            }
            val bodyLength = r.offset
            val signature = r.bytes(64)
            if (r.remaining != 0) throw DollyException(DollyError.MalformedPacket)

            if (!Crypto.verify(identityKey, SIGNATURE_DOMAIN + data.copyOfRange(0, bodyLength), signature)) {
                throw DollyException(DollyError.BadSignature)
            }
            if (expiry <= now) throw DollyException(DollyError.Expired)
            return Ticket(identityKey, staticKey, ephemeralKey, expiry, endpoints, signature)
        }
    }

    internal fun body(): ByteArray {
        val w = ByteWriter()
        w.u8(VERSION)
        w.u8(SUITE_CLASSICAL)
        w.bytes(identityKey)
        w.bytes(staticKey)
        w.bytes(ephemeralKey)
        w.u64(expiry)
        w.u8(endpoints.size)
        for (e in endpoints) {
            w.u8(e.kind.code)
            w.bytes(e.address)
            w.u16(e.port)
        }
        return w.toByteArray()
    }

    fun encoded(): ByteArray = body() + signature
}
