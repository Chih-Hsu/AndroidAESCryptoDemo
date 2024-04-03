package com.chihweihsu.androidcrypto.domain

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class CryptoManager {

    /**
     * @param [AndroidKeyStore] 是特定值，不能隨意更改
     */
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    // Create a new key if it doesn't exist
    private fun getKey(): SecretKey {
        val existingKey = keyStore.getEntry("secret", null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    private fun createKey(): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init(
                KeyGenParameterSpec.Builder("secret", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(BLOCK_MODE)
                    .setEncryptionPaddings(PADDING)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
    }

    private val encryptionCipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE, getKey())
    }

    private fun getDecryptionCipher(iv: ByteArray): Cipher {
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getKey(), IvParameterSpec(iv))
        }
    }

    fun encrypt(message: String, outputStream: OutputStream, context: Context): ByteArray {
        val encryptedBytes = encryptionCipher.doFinal(message.encodeToByteArray())
        outputStream.use {
            it.write(encryptionCipher.iv.size)
            it.write(encryptionCipher.iv)
            it.write(encryptedBytes.size)
            it.write(encryptedBytes)
        }

        /** SharedPreferences Test */
        Injection.provideEncryptedSharedPreferences(context).edit().putString("encrypted", message).apply()
        Injection.provideSharedPreferences(context).edit().putString("unencrypted", message).apply()

        return encryptedBytes
    }

    fun decrypt(inputStream: InputStream, context: Context): ByteArray {
        return inputStream.use {
            val ivSize = it.read()
            val iv = ByteArray(ivSize)
            it.read(iv)
            val encryptedByteSize = it.read()
            val encryptedBytes = ByteArray(encryptedByteSize)
            it.read(encryptedBytes)
            getDecryptionCipher(iv).doFinal(encryptedBytes).also {
                Injection.provideEncryptedSharedPreferences(context).getString("encrypted", "")?.let { message ->
                    Log.d("CryptoManager", "Encrypted: $message")
                }
            }
        }
    }


    companion object {
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}
