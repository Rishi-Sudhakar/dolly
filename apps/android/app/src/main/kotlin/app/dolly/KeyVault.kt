package app.dolly

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.dolly.core.Store
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Custody of the store's master key. An AES key that never leaves the Android Keystore (StrongBox when the
 * phone has it, otherwise the TEE) wraps a random 32-byte master key, which is kept in a file excluded from
 * backup: iv (12 bytes) || ciphertext || tag.
 */
object KeyVault {
    private const val ALIAS = "dolly.master"
    private const val FILE = "master.key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128

    fun masterKey(context: Context): ByteArray {
        val file = File(context.noBackupFilesDir, FILE)
        val wrapper = wrapper()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        if (file.exists()) {
            val blob = file.readBytes()
            cipher.init(Cipher.DECRYPT_MODE, wrapper, GCMParameterSpec(TAG_BITS, blob, 0, IV_LENGTH))
            return cipher.doFinal(blob, IV_LENGTH, blob.size - IV_LENGTH)
        }
        val master = Store.newMasterKey()
        cipher.init(Cipher.ENCRYPT_MODE, wrapper)
        val pending = File(file.path + ".tmp")
        pending.writeBytes(cipher.iv + cipher.doFinal(master))
        Files.move(pending.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        return master
    }

    private fun wrapper(): SecretKey {
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keystore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec) }
            .generateKey()
    }
}
