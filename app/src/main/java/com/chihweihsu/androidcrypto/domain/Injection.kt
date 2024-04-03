package com.chihweihsu.androidcrypto.domain

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object Injection {

    fun provideEncryptedSharedPreferences(context: Context): SharedPreferences {

        /** Step 1: Create a MasterKey which will be used to encrypt/decrypt the SharedPreferences */
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        /** Step 2: Create an instance of EncryptedSharedPreferences */
        return EncryptedSharedPreferences.create(
            context,
            "encrypted_preferences",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun provideSharedPreferences(context: Context): SharedPreferences {
        return context.getSharedPreferences("unencrypted_preferences", Context.MODE_PRIVATE)
    }

    /**
     * MasterKey（主密鑰）:
     * 主密鑰通常是指一個在系統中用於加密和保護其他密鑰或資料的主要密鑰。
     * 這個主密鑰通常是由系統或應用程序自行生成並管理的，其安全性和機密性非常重要，因為它是整個加密系統的核心。
     * 主密鑰可能被用於加密其他敏感資訊、密碼、金鑰等，或者用於生成和管理其他子密鑰。
     * 在密碼學中，主密鑰的安全性直接影響到整個系統的安全性。
     *
     * KeyStore（金鑰庫）:
     * 金鑰庫是一個存儲和管理密鑰、證書和信任錨點的安全存儲區域。
     * 它通常用於 Android 和 Java 等平台上，用於保存應用程式需要用到的加密金鑰、證書等敏感資訊。
     * 金鑰庫可以是系統級的（系統金鑰庫），也可以是應用程序級的（應用金鑰庫）。
     * 應用程序可以通過金鑰庫來安全地存儲和檢索金鑰，以及對敏感資訊進行加密和解密操作。
     * 金鑰庫通常受到許多安全機制的保護，例如密碼保護、訪問控制、加密等。
     */

}