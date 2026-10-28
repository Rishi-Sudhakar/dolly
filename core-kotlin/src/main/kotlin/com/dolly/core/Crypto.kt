package com.dolly.core

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Thin wrappers over the platform JCA. No third-party code. Needs X25519/Ed25519 (JDK 15+, Android 13+). */
internal object Crypto {
    private val X25519_PKCS8 = "302e020100300506032b656e04220420".hexToBytes()
    private val X25519_SPKI = "302a300506032b656e032100".hexToBytes()
    private val ED25519_PKCS8 = "302e020100300506032b657004220420".hexToBytes()
    private val ED25519_SPKI = "302a300506032b6570032100".hexToBytes()

    fun x25519Generate(): KeyPair25519 {
        val pair = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        return KeyPair25519(pair.private.encoded.takeLast(32).toByteArray(), pair.public.encoded.takeLast(32).toByteArray())
    }

    fun ed25519Generate(): KeyPair25519 {
        val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        return KeyPair25519(pair.private.encoded.takeLast(32).toByteArray(), pair.public.encoded.takeLast(32).toByteArray())
    }

    fun dh(seed: ByteArray, peerPublic: ByteArray): ByteArray {
        val kf = KeyFactory.getInstance("X25519")
        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(kf.generatePrivate(PKCS8EncodedKeySpec(X25519_PKCS8 + seed)))
        agreement.doPhase(kf.generatePublic(X509EncodedKeySpec(X25519_SPKI + peerPublic)), true)
        return agreement.generateSecret()
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val signature = Signature.getInstance("Ed25519")
        signature.initSign(KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(ED25519_PKCS8 + seed)))
        signature.update(message)
        return signature.sign()
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(ED25519_SPKI + publicKey)))
        verifier.update(message)
        verifier.verify(signature)
    } catch (e: Exception) {
        false
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.ifEmpty { ByteArray(32) }, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 HKDF-SHA256. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray {
        val prk = hmac(salt, ikm)
        val infoBytes = info.toByteArray()
        var previous = ByteArray(0)
        val out = java.io.ByteArrayOutputStream()
        var counter = 1
        while (out.size() < length) {
            previous = hmac(prk, previous + infoBytes + byteArrayOf(counter.toByte()))
            out.write(previous)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    /** ChaCha20-Poly1305; returns ciphertext || 16-byte tag. */
    fun seal(key: ByteArray, nonce: ByteArray, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    fun open(key: ByteArray, nonce: ByteArray, ad: ByteArray, sealed: ByteArray): ByteArray = try {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(ad)
        cipher.doFinal(sealed)
    } catch (e: Exception) {
        throw DollyException(DollyError.AuthenticationFailed)
    }
}

/** A raw 32-byte private seed and its public key. */
class KeyPair25519(val seed: ByteArray, val publicKey: ByteArray)

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd-length hex" }
    return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
