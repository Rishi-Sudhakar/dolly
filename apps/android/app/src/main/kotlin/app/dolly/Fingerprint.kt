package app.dolly

import com.dolly.core.Crypto
import com.dolly.core.toHex

object Fingerprint {
    /** Short, human-comparable digest of an identity key: "a1b2 c3d4 e5f6 0718 293a". */
    fun of(identityKey: ByteArray): String =
        Crypto.sha256(identityKey).copyOf(10).toHex().chunked(4).joinToString(" ")
}
