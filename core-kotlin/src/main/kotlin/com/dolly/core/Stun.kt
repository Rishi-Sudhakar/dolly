package com.dolly.core

/** Minimal STUN (RFC 5389) Binding client codec: learn the public IP:port a NAT assigned to a socket. */
object Stun {
    const val MAGIC_COOKIE = 0x2112A442L
    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_SUCCESS = 0x0101
    private const val ATTR_MAPPED_ADDRESS = 0x0001
    private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020

    enum class MappingBehavior {
        /** Same public port for every destination: hole punching normally works. */
        EndpointIndependent,
        /** Different public port per destination: hole punching usually fails. */
        Symmetric,
        Unknown,
    }

    fun newTransactionId(): ByteArray = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }

    fun bindingRequest(transactionId: ByteArray): ByteArray {
        require(transactionId.size == 12) { "STUN transaction IDs are 12 bytes" }
        return ByteWriter().apply {
            u16(BINDING_REQUEST)
            u16(0)
            u32(MAGIC_COOKIE)
            bytes(transactionId)
        }.toByteArray()
    }

    fun parseBindingResponse(data: ByteArray, transactionId: ByteArray): Endpoint = try {
        parse(data, transactionId)
    } catch (e: DollyException) {
        throw DollyException(DollyError.BadStunResponse)
    }

    /** Compare the mapped endpoints different STUN servers reported for the same local socket. */
    fun mappingBehavior(results: List<Endpoint>): MappingBehavior {
        if (results.size < 2) return MappingBehavior.Unknown
        return if (results.all { it.sameAs(results[0]) }) MappingBehavior.EndpointIndependent else MappingBehavior.Symmetric
    }

    private fun bad(): Nothing = throw DollyException(DollyError.BadStunResponse)

    private fun parse(data: ByteArray, transactionId: ByteArray): Endpoint {
        val r = ByteReader(data)
        if (r.u16() != BINDING_SUCCESS) bad()
        val length = r.u16()
        if (r.u32() != MAGIC_COOKIE) bad()
        if (!r.bytes(12).contentEquals(transactionId)) bad()
        val attributes = ByteReader(r.bytes(length))

        var plainMapped: Endpoint? = null
        while (attributes.remaining >= 4) {
            val type = attributes.u16()
            val valueLength = attributes.u16()
            val value = attributes.bytes(valueLength)
            attributes.bytes(minOf((4 - valueLength % 4) % 4, attributes.remaining))  // padding
            when (type) {
                ATTR_XOR_MAPPED_ADDRESS -> return decodeAddress(value, xor = true, transactionId = transactionId)
                ATTR_MAPPED_ADDRESS -> plainMapped = decodeAddress(value, xor = false, transactionId = transactionId)
            }
        }
        return plainMapped ?: bad()
    }

    private fun decodeAddress(value: ByteArray, xor: Boolean, transactionId: ByteArray): Endpoint {
        val r = ByteReader(value)
        r.u8()
        val family = r.u8()
        var port = r.u16()
        val mask = ByteWriter().apply { u32(MAGIC_COOKIE); bytes(transactionId) }.toByteArray()
        if (xor) port = port xor (MAGIC_COOKIE shr 16).toInt()

        val length = when (family) {
            1 -> 4
            2 -> 16
            else -> bad()
        }
        val address = r.bytes(length)
        if (xor) for (i in 0 until length) address[i] = (address[i].toInt() xor mask[i].toInt()).toByte()
        return Endpoint(if (family == 1) Endpoint.Kind.V4 else Endpoint.Kind.V6, address, port)
    }
}
