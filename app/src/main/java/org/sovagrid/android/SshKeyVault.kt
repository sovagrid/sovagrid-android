/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.util.AtomicFile
import org.json.JSONObject
import org.sovagrid.ssh.DeviceSshKey
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.util.Base64
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Only AES-GCM ciphertext is persisted. Wrapping keys stay in Android Keystore. */
internal class SshKeyVault(context: Context) {
    private val directory = File(context.noBackupFilesDir, "ssh-keys")
    private val keyStore: KeyStore get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun file(id: String): File {
        require(SshKeyReference.validId(id)) { "Invalid saved SSH key" }
        return File(directory, "$id.json")
    }

    fun all(): List<SshKeyMetadata> = synchronized(lock) {
        if (!directory.exists()) return@synchronized emptyList()
        val files = directory.listFiles { entry -> entry.name.endsWith(".json") }
            ?: throw IOException("Saved keys unavailable")
        if (files.size > MAX_KEYS) throw IOException("Too many saved keys")
        files.map { entry -> read(entry.name.removeSuffix(".json")).first }.sortedByDescending { it.createdAt }
    }

    fun create(label: String): SshKeyMetadata = synchronized(lock) {
        require(validLabel(label)) { "Введите название ключа от 1 до 80 символов без переносов." }
        if (all().size >= MAX_KEYS) throw IOException("Сначала удалите неиспользуемый ключ: доступно до 64 ключей.")
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Key directory unavailable")
        Os.chmod(directory.path, 0x1c0) // 0700
        val id = UUID.randomUUID().toString()
        val seed = DeviceSshKey.generateSeed()
        var saved = false
        try {
            val metadata = SshKeyMetadata(id, label, DeviceSshKey.publicKey(seed, comment(id)), System.currentTimeMillis() / 1000)
            val alias = alias(id)
            check(!keyStore.containsAlias(alias))
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build())
            val sealed = SshKeyEnvelope.encrypt(seed, generator.generateKey(), metadata)
            val encoder = Base64.getEncoder()
            val bytes = JSONObject().apply {
                put("version", 1); put("id", id); put("label", label); put("public_key", metadata.publicKey)
                put("created_at", metadata.createdAt); put("nonce", encoder.encodeToString(sealed.nonce))
                put("ciphertext", encoder.encodeToString(sealed.ciphertext))
            }.toString().toByteArray(Charsets.UTF_8)
            val atomic = AtomicFile(file(id))
            val stream = atomic.startWrite()
            try {
                Os.fchmod(stream.fd, 0x180) // 0600, including AtomicFile's staging file
                stream.write(bytes)
                atomic.finishWrite(stream)
            } catch (error: Exception) {
                atomic.failWrite(stream)
                throw error
            }
            saved = true
            metadata
        } finally {
            seed.fill(0)
            if (!saved) { AtomicFile(file(id)).delete(); runCatching { keyStore.deleteEntry(alias(id)) } }
        }
    }

    fun privateKeyText(id: String): String = synchronized(lock) {
        val (metadata, sealed) = read(id)
        val key = keyStore.getKey(alias(id), null) as? SecretKey ?: throw IOException("Device key unavailable")
        val seed = SshKeyEnvelope.decrypt(sealed, key, metadata)
        try {
            if (DeviceSshKey.publicKey(seed, comment(id)) != metadata.publicKey) throw IOException("Saved key mismatch")
            DeviceSshKey.privateKey(seed)
        } finally { seed.fill(0) }
    }

    fun publicKey(id: String): SshKeyMetadata = synchronized(lock) {
        val (metadata, sealed) = read(id)
        val key = keyStore.getKey(alias(id), null) as? SecretKey ?: throw IOException("Device key unavailable")
        val seed = SshKeyEnvelope.decrypt(sealed, key, metadata)
        try {
            if (DeviceSshKey.publicKey(seed, comment(id)) != metadata.publicKey) throw IOException("Saved key mismatch")
            metadata
        } finally { seed.fill(0) }
    }

    fun delete(id: String) = synchronized(lock) {
        val target = file(id)
        if (!target.isFile) throw IOException("Saved key unavailable")
        AtomicFile(target).delete()
        if (target.exists()) throw IOException("Saved key could not be removed")
        keyStore.deleteEntry(alias(id))
    }

    private fun read(id: String): Pair<SshKeyMetadata, SealedSshSeed> {
        val atomic = AtomicFile(file(id))
        val bytes = atomic.openRead().use { stream ->
            val data = stream.readBytesBounded(8192)
            if (data.isEmpty()) throw IOException("Saved key is empty")
            data
        }
        val item = JSONObject(String(bytes, Charsets.UTF_8))
        if (item.get("version") != 1 || item.get("id") != id) throw IOException("Invalid saved key metadata")
        val label = item.get("label") as? String ?: throw IOException("Invalid key label")
        val public = item.get("public_key") as? String ?: throw IOException("Invalid public key")
        val created = when (val value = item.get("created_at")) {
            is Int -> value.toLong()
            is Long -> value
            else -> throw IOException("Invalid key timestamp")
        }
        if (!validLabel(label) || created < 0 ||
            !public.matches(Regex("ssh-ed25519 [A-Za-z0-9+/]{68} ${comment(id)}"))) throw IOException("Invalid saved key metadata")
        val decoder = Base64.getDecoder()
        val sealed = SealedSshSeed(decoder.decode(item.getString("nonce")), decoder.decode(item.getString("ciphertext")))
        if (sealed.nonce.size != 12 || sealed.ciphertext.size != 48) throw IOException("Invalid encrypted key")
        return SshKeyMetadata(id, label, public, created) to sealed
    }

    private fun java.io.InputStream.readBytesBounded(maximum: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (true) {
            val count = read(buffer)
            if (count < 0) break
            if (output.size() + count > maximum) throw IOException("Saved key too large")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    companion object {
        private val lock = Any()
        private const val MAX_KEYS = 64
        private fun alias(id: String) = "org.sovagrid.ssh.$id"
        private fun comment(id: String) = "sovagrid-android-${id.take(8)}"
        private fun validLabel(label: String) = label.isNotBlank() && label.length <= 80 &&
            label == label.trim() && label.none { Character.isISOControl(it) || it == '\u2028' || it == '\u2029' }
    }
}
