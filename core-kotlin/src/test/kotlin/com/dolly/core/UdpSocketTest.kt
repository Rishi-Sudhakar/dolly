package com.dolly.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class UdpSocketTest {
    private val ip6 = ByteArray(16).also { it[15] = 1 }  // ::1
    private val ip4 = byteArrayOf(127, 0, 0, 1)

    @Test
    fun datagramsKeepTheirAddressFamily() {
        UdpSocket().use { a ->
            UdpSocket().use { b ->
                a.send("six".toByteArray(), Endpoint(Endpoint.Kind.V6, ip6, b.localPort))
                val (six, sixFrom) = b.receive(1000)!!
                assertContentEquals("six".toByteArray(), six)
                assertEquals(Endpoint(Endpoint.Kind.V6, ip6, a.localPort), sixFrom)

                a.send("four".toByteArray(), Endpoint(Endpoint.Kind.V4, ip4, b.localPort))
                val (four, fourFrom) = b.receive(1000)!!
                assertContentEquals("four".toByteArray(), four)
                assertEquals(Endpoint(Endpoint.Kind.V4, ip4, a.localPort), fourFrom)
            }
        }
    }
}
