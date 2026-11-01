/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.content.ContentResolver
import android.net.Uri
import android.os.CancellationSignal
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.Os
import android.system.OsConstants
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.FileTime
import java.security.SecureRandom

internal object PanelRestoreContract {
    const val FILE_BYTES = 8L * 1024 * 1024 * 1024
    const val TOTAL_BYTES = 16L * 1024 * 1024 * 1024
    const val READ_BYTES = 256 * 1024
    const val COPY_MESSAGE = "Выберите до пяти обычных файлов копии. Если хранилище не поддерживает чтение по частям, скопируйте их на устройство и выберите снова."
    fun token(value: Any?, length: Int = 32): String? = (value as? String)?.takeIf {
        it.length == length && it.all { char -> char in 'a'..'f' || char in '0'..'9' }
    }
    fun offset(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }?.takeIf { it in 0..FILE_BYTES }
    fun range(size: Long, offset: Long, length: Long): Boolean =
        size in 1..FILE_BYTES && offset >= 0 && length in 1..READ_BYTES.toLong() &&
            offset <= size && length <= size - offset
}

internal data class PanelRestoreMessage(val action: String, val session: String, val id: String,
    val handle: String? = null, val offset: Long? = null, val length: Int? = null) {
    companion object {
        fun decode(fields: Map<String, Any?>): PanelRestoreMessage? {
            val action = fields["action"] as? String ?: return null
            val session = PanelRestoreContract.token(fields["session"]) ?: return null
            val id = PanelRestoreContract.token(fields["id"]) ?: return null
            val expected = if (action == "read") setOf("action", "session", "id", "handle", "offset", "length")
                else if (action in setOf("pick", "release")) setOf("action", "session", "id") else return null
            if (fields.keys != expected) return null
            if (action != "read") return PanelRestoreMessage(action, session, id)
            val handle = PanelRestoreContract.token(fields["handle"], 64) ?: return null
            val offset = PanelRestoreContract.offset(fields["offset"]) ?: return null
            val length = PanelRestoreContract.offset(fields["length"])?.takeIf { it in 1..PanelRestoreContract.READ_BYTES.toLong() }
                ?: return null
            return PanelRestoreMessage(action, session, id, handle, offset, length.toInt())
        }
    }
}

internal data class PanelRestoreDescriptor(val handle: String, val name: String, val size: Long)

/** Retains only selected regular seekable FDs; neither paths nor bytes are copied. */
internal class PanelRestoreFiles : AutoCloseable {
    private data class Held(val descriptor: ParcelFileDescriptor, val name: String,
                            val size: Long, val fingerprint: List<Long>)
    private val entries = mutableMapOf<String, Held>()
    private val random = SecureRandom()
    private var closed = false

    private fun fingerprint(descriptor: ParcelFileDescriptor): List<Long> {
        val stat = Os.fstat(descriptor.fileDescriptor)
        if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_size !in 1..PanelRestoreContract.FILE_BYTES || stat.st_nlink < 1)
            throw IOException(PanelRestoreContract.COPY_MESSAGE)
        val times = if (Build.VERSION.SDK_INT >= 27) {
            listOf(stat.st_mtim.tv_sec, stat.st_mtim.tv_nsec, stat.st_ctim.tv_sec, stat.st_ctim.tv_nsec)
        } else {
            // API26 has no public StructStat timespec fields. The proc link
            // identifies the retained FD, never a provider-controlled pathname.
            val path = Paths.get("/proc/self/fd/${descriptor.fd}")
            val modified = Files.getLastModifiedTime(path).toInstant()
            val changed = (Files.getAttribute(path, "unix:ctime") as? FileTime)?.toInstant()
                ?: throw IOException(PanelRestoreContract.COPY_MESSAGE)
            listOf(modified.epochSecond, modified.nano.toLong(), changed.epochSecond, changed.nano.toLong())
        }
        return listOf(stat.st_dev, stat.st_ino, stat.st_size, stat.st_mode.toLong(), stat.st_nlink,
            stat.st_uid.toLong(), stat.st_gid.toLong()) + times
    }

    fun add(resolver: ContentResolver, uri: Uri, cancellation: CancellationSignal): PanelRestoreDescriptor {
        if (uri.scheme != "content") throw IOException(PanelRestoreContract.COPY_MESSAGE)
        val name = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, cancellation)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        } ?: throw IOException(PanelRestoreContract.COPY_MESSAGE)
        if (!PanelFileContract.safeFilename(name)) throw IOException(PanelRestoreContract.COPY_MESSAGE)
        val descriptor = resolver.openFileDescriptor(uri, "r", cancellation)
            ?: throw IOException(PanelRestoreContract.COPY_MESSAGE)
        try {
            val proof = fingerprint(descriptor)
            val size = proof[2]
            if (Os.lseek(descriptor.fileDescriptor, 0, OsConstants.SEEK_CUR) < 0)
                throw IOException(PanelRestoreContract.COPY_MESSAGE)
            synchronized(this) {
                if (closed || entries.size >= 5 || size > PanelRestoreContract.TOTAL_BYTES - entries.values.sumOf { it.size })
                    throw IOException(PanelRestoreContract.COPY_MESSAGE)
                val handle = ByteArray(32).also(random::nextBytes).joinToString("") { "%02x".format(it) }
                check(!entries.containsKey(handle))
                entries[handle] = Held(descriptor, name, size, proof)
                return PanelRestoreDescriptor(handle, name, size)
            }
        } catch (error: Exception) { descriptor.close(); throw error }
    }

    fun read(handle: String, offset: Long, length: Int): ByteArray {
        val pair = synchronized(this) {
            val held = entries[handle] ?: throw IOException("Выбор файлов уже закрыт.")
            if (!PanelRestoreContract.range(held.size, offset, length.toLong())) throw IOException("Неверный диапазон чтения.")
            held to ParcelFileDescriptor.dup(held.descriptor.fileDescriptor)
        }
        val (held, duplicate) = pair
        duplicate.use { descriptor ->
            if (fingerprint(descriptor) != held.fingerprint) throw IOException("Файл изменился. Выберите копию снова.")
            val result = ByteArray(length)
            var position = 0
            while (position < length) {
                val count = Os.pread(descriptor.fileDescriptor, result, position, length - position, offset + position)
                if (count <= 0) throw IOException("Файл прочитан не полностью.")
                position += count
            }
            if (fingerprint(descriptor) != held.fingerprint) { result.fill(0); throw IOException("Файл изменился. Выберите копию снова.") }
            synchronized(this) {
                if (entries[handle] !== held) { result.fill(0); throw IOException("Выбор файлов уже закрыт.") }
            }
            return result
        }
    }

    @Synchronized override fun close() {
        closed = true
        entries.values.forEach { try { it.descriptor.close() } catch (_: Exception) { } }
        entries.clear()
    }
}
