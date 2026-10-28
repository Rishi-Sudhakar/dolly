package com.dolly.core

/**
 * An established, authenticated channel with one peer: handshake output plus a Double Ratchet.
 *
 * The peer with the lexicographically lower identity key is the initiator. The responder can
 * only send after it has received one packet, so the initiator should send a hello on connect.
 */
class Session(
    identity: Identity,
    ephemeral: KeyPair25519,
    localTicket: Ticket,
    remoteTicket: Ticket,
    private val generate: () -> KeyPair25519 = { Crypto.x25519Generate() },
) {
    companion object {
        const val MAX_SKIPPED = 1000
        private val BUCKETS = intArrayOf(256, 512, 1024)
        private const val HEADER_LENGTH = 40
        private const val PACKET_VERSION = 1
        private const val PACKET_TYPE_DATA = 1
        private const val TAG_LENGTH = 16

        /** Largest payload that fits the biggest padding bucket (2 bytes are the length prefix). */
        val MAX_PAYLOAD = BUCKETS.last() - 2
    }

    private class State(
        var rootKey: ByteArray,
        var dhs: KeyPair25519,
        var dhr: ByteArray?,
        var cks: ByteArray?,
        var ckr: ByteArray? = null,
        var ns: Long = 0,
        var nr: Long = 0,
        var pn: Long = 0,
        val skipped: LinkedHashMap<String, ByteArray> = LinkedHashMap(),
    ) {
        fun copy() = State(rootKey, dhs, dhr, cks, ckr, ns, nr, pn, LinkedHashMap(skipped))
    }

    private var state: State
    private val adPrefix: ByteArray
    val isInitiator: Boolean
    val peerIdentityKey: ByteArray = remoteTicket.identityKey

    /** Authenticates transport datagrams (punches, acks, data). Both peers derive the same key from the handshake. */
    val transportKey: ByteArray

    val canSend: Boolean get() = state.cks != null

    init {
        if (localTicket.identityKey.contentEquals(remoteTicket.identityKey)) throw DollyException(DollyError.SameIdentity)
        isInitiator = localTicket.identityKey.compareUnsigned(remoteTicket.identityKey) < 0
        val (a, b) = if (isInitiator) localTicket to remoteTicket else remoteTicket to localTicket

        // dh1 = DH(static_A, eph_B), dh2 = DH(eph_A, static_B), dh3 = DH(eph_A, eph_B)
        val dh1 = if (isInitiator) Crypto.dh(identity.agreement.seed, remoteTicket.ephemeralKey)
        else Crypto.dh(ephemeral.seed, remoteTicket.staticKey)
        val dh2 = if (isInitiator) Crypto.dh(ephemeral.seed, remoteTicket.staticKey)
        else Crypto.dh(identity.agreement.seed, remoteTicket.ephemeralKey)
        val dh3 = Crypto.dh(ephemeral.seed, remoteTicket.ephemeralKey)

        val transcript = Crypto.sha256(a.encoded() + b.encoded())
        val rootKey = Crypto.hkdf(dh1 + dh2 + dh3, transcript, "dolly/v1/handshake", 32)
        transportKey = Crypto.hkdf(rootKey, ByteArray(0), "dolly/v1/transport", 32)
        adPrefix = "dolly/v1/msg".toByteArray() + a.identityKey + b.identityKey

        state = if (isInitiator) {
            val dhs = generate()
            val (rk, cks) = kdfRoot(rootKey, Crypto.dh(dhs.seed, remoteTicket.ephemeralKey))
            State(rk, dhs, remoteTicket.ephemeralKey, cks)
        } else {
            State(rootKey, ephemeral, null, null)
        }
    }

    // region Send

    fun encrypt(payload: ByteArray): ByteArray {
        val cks = state.cks ?: throw DollyException(DollyError.NotReadyToSend)
        if (payload.size > MAX_PAYLOAD) throw DollyException(DollyError.MessageTooLarge)

        val (messageKey, nextChain) = kdfChain(cks)
        val header = ByteWriter().apply {
            bytes(state.dhs.publicKey)
            u32(state.pn)
            u32(state.ns)
        }.toByteArray()

        val sealed = seal(pad(payload), messageKey, adPrefix + header)
        state.cks = nextChain
        state.ns += 1

        return ByteWriter().apply {
            u8(PACKET_VERSION)
            u8(PACKET_TYPE_DATA)
            bytes(header)
            bytes(sealed)
        }.toByteArray()
    }

    // endregion

    // region Receive

    /** Decrypts a packet. A packet that fails authentication leaves the session state untouched. */
    fun decrypt(packet: ByteArray): ByteArray {
        val r = ByteReader(packet)
        if (r.u8() != PACKET_VERSION) throw DollyException(DollyError.BadVersion)
        if (r.u8() != PACKET_TYPE_DATA) throw DollyException(DollyError.MalformedPacket)
        val headerBytes = r.bytes(HEADER_LENGTH)
        val h = ByteReader(headerBytes)
        val dh = h.bytes(32)
        val pn = h.u32()
        val n = h.u32()
        val sealed = r.bytes(r.remaining)
        if (sealed.size < TAG_LENGTH) throw DollyException(DollyError.MalformedPacket)

        val s = state.copy()
        val ad = adPrefix + headerBytes
        val id = skippedId(dh, n)
        val plaintext: ByteArray

        val stored = s.skipped[id]
        if (stored != null) {
            plaintext = open(sealed, stored, ad)
            s.skipped.remove(id)
        } else {
            val currentRemote = s.dhr
            if (currentRemote == null || !currentRemote.contentEquals(dh)) {
                if (currentRemote != null && s.ckr != null) skipKeys(s, pn)
                dhRatchet(s, dh)
            }
            skipKeys(s, n)
            val ckr = s.ckr ?: throw DollyException(DollyError.AuthenticationFailed)
            val (messageKey, nextChain) = kdfChain(ckr)
            plaintext = open(sealed, messageKey, ad)
            s.ckr = nextChain
            s.nr += 1
        }
        state = s
        return unpad(plaintext)
    }

    private fun skipKeys(s: State, until: Long) {
        if (s.nr >= until) return
        var chain = s.ckr
        val dhr = s.dhr
        if (until - s.nr > MAX_SKIPPED || chain == null || dhr == null) throw DollyException(DollyError.TooManySkippedKeys)
        while (s.nr < until) {
            val (messageKey, next) = kdfChain(chain!!)
            s.skipped[skippedId(dhr, s.nr)] = messageKey
            if (s.skipped.size > MAX_SKIPPED) s.skipped.remove(s.skipped.keys.first())
            chain = next
            s.nr += 1
        }
        s.ckr = chain
    }

    private fun dhRatchet(s: State, remote: ByteArray) {
        s.pn = s.ns
        s.ns = 0
        s.nr = 0
        s.dhr = remote
        val (rk1, ckr) = kdfRoot(s.rootKey, Crypto.dh(s.dhs.seed, remote))
        s.ckr = ckr
        s.dhs = generate()
        val (rk2, cks) = kdfRoot(rk1, Crypto.dh(s.dhs.seed, remote))
        s.rootKey = rk2
        s.cks = cks
    }

    // endregion

    // region Primitives

    private fun skippedId(dh: ByteArray, n: Long) = dh.toHex() + ":" + n

    private fun kdfRoot(rootKey: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
        val out = Crypto.hkdf(dhOut, rootKey, "dolly/v1/ratchet", 64)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 64)
    }

    private fun kdfChain(chainKey: ByteArray): Pair<ByteArray, ByteArray> =
        Crypto.hmac(chainKey, byteArrayOf(0x01)) to Crypto.hmac(chainKey, byteArrayOf(0x02))

    /** Message key -> 32-byte AEAD key + 12-byte nonce. Each message key is used exactly once. */
    private fun aeadParams(messageKey: ByteArray): Pair<ByteArray, ByteArray> {
        val out = Crypto.hkdf(messageKey, ByteArray(0), "dolly/v1/msg-key", 44)
        return out.copyOfRange(0, 32) to out.copyOfRange(32, 44)
    }

    private fun seal(plaintext: ByteArray, messageKey: ByteArray, ad: ByteArray): ByteArray {
        val (key, nonce) = aeadParams(messageKey)
        return Crypto.seal(key, nonce, ad, plaintext)
    }

    private fun open(sealed: ByteArray, messageKey: ByteArray, ad: ByteArray): ByteArray {
        val (key, nonce) = aeadParams(messageKey)
        return Crypto.open(key, nonce, ad, sealed)
    }

    // endregion

    // region Padding (hides message length within a bucket)

    private fun pad(payload: ByteArray): ByteArray {
        val framed = ByteWriter().apply { u16(payload.size); bytes(payload) }.toByteArray()
        val target = BUCKETS.first { it >= framed.size }
        return framed.copyOf(target)
    }

    private fun unpad(padded: ByteArray): ByteArray {
        val r = ByteReader(padded)
        val length = r.u16()
        if (length > r.remaining) throw DollyException(DollyError.MalformedPacket)
        return r.bytes(length)
    }

    // endregion
}
