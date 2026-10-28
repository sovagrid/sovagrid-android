/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class SshKeyMetadata(val id: String, val label: String, val publicKey: String, val createdAt: Long) {
    fun associatedData(): ByteArray = ByteArrayOutputStream().use { bytes ->
        DataOutputStream(bytes).use { output ->
            output.writeInt(1)
            output.writeLong(createdAt)
            for (field in listOf(id, label, publicKey)) {
                val encoded = field.toByteArray(Charsets.UTF_8)
                output.writeInt(encoded.size)
                output.write(encoded)
            }
        }
        bytes.toByteArray()
    }
}

internal data class SealedSshSeed(val nonce: ByteArray, val ciphertext: ByteArray)

internal object SshKeyEnvelope {
    fun encrypt(seed: ByteArray, key: SecretKey, metadata: SshKeyMetadata): SealedSshSeed {
        require(seed.size == 32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(metadata.associatedData())
        val ciphertext = cipher.doFinal(seed)
        check(cipher.iv.size == 12 && ciphertext.size == 48)
        return SealedSshSeed(cipher.iv, ciphertext)
    }

    fun decrypt(sealed: SealedSshSeed, key: SecretKey, metadata: SshKeyMetadata): ByteArray {
        require(sealed.nonce.size == 12 && sealed.ciphertext.size == 48)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.nonce))
        cipher.updateAAD(metadata.associatedData())
        return cipher.doFinal(sealed.ciphertext).also { check(it.size == 32) }
    }
}

/** Opaque references are local selections, never file paths or exported private keys. */
internal object SshKeyReference {
    private val idPattern = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    fun validId(id: String): Boolean = idPattern.matches(id)
    fun uri(id: String): String { require(validId(id)); return "sovagrid-key:$id" }
    fun id(uri: String): String? = uri.removePrefix("sovagrid-key:").takeIf {
        uri.startsWith("sovagrid-key:") && validId(it)
    }
}
