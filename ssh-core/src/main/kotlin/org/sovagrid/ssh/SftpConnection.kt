/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.DirectConnection
import net.schmizz.sshj.sftp.FileAttributes
import net.schmizz.sshj.sftp.FileMode
import net.schmizz.sshj.sftp.OpenMode
import net.schmizz.sshj.sftp.SFTPClient
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.EnumSet
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean

/** Absolute POSIX paths. Names come from SFTP or Android's document provider, never a shell. */
object RemotePath {
    fun normalize(path: String): String {
        require(path.startsWith('/')) { "Expected absolute remote path" }
        require(path.none { it == '\u0000' || it.code < 32 || it.code == 127 }) { "Invalid remote path" }
        val parts = ArrayList<String>()
        path.split('/').forEach { part ->
            when (part) {
                "", "." -> Unit
                ".." -> if (parts.isNotEmpty()) parts.removeAt(parts.lastIndex)
                else -> parts.add(part)
            }
        }
        return "/" + parts.joinToString("/")
    }

    fun child(parent: String, name: String): String {
        require(name.isNotEmpty() && name != "." && name != ".." && '/' !in name &&
            name.none { it == '\u0000' || it.code < 32 || it.code == 127 }) { "Invalid file name" }
        return normalize(normalize(parent).trimEnd('/') + "/" + name)
    }

    fun parent(path: String): String {
        val clean = normalize(path)
        return if (clean == "/") "/" else clean.substringBeforeLast('/').ifEmpty { "/" }
    }
}

data class RemoteEntry(val name: String, val isDirectory: Boolean, val isFile: Boolean, val size: Long)

/** A single authenticated SFTP connection. Caller serializes operations and may close concurrently to cancel I/O. */
class SftpConnection internal constructor(
    private val client: SSHClient,
    private val sftp: SFTPClient,
    private val gateway: SSHClient?,
    private val channel: DirectConnection?
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    val isOpen: Boolean get() = !closed.get() && client.isConnected && gateway?.isConnected != false

    fun home(): String = checked { RemotePath.normalize(sftp.canonicalize(".")) }

    fun list(path: String): List<RemoteEntry> = checked {
        val canonical = RemotePath.normalize(path)
        sftp.ls(canonical).asSequence()
            .filter { it.name != "." && it.name != ".." }
            .mapNotNull { item ->
                if (runCatching { RemotePath.child(canonical, item.name) }.isFailure) null
                else RemoteEntry(item.name, item.isDirectory, item.isRegularFile, item.attributes.size)
            }
            .sortedWith(compareByDescending<RemoteEntry> { it.isDirectory }.thenBy { it.name.lowercase() })
            .toList()
    }

    /** Streams bytes without text conversion. The caller owns and closes output, including on failure. */
    fun download(path: String, output: OutputStream, cancelled: () -> Boolean = { false },
                 progress: (Long, Long) -> Unit = { _, _ -> }) {
        checked {
            val clean = RemotePath.normalize(path)
            val attributes = sftp.stat(clean)
            if (attributes.type != FileMode.Type.REGULAR) throw IOException("Not a regular file")
            val total = attributes.size
            var offset = 0L
            val buffer = ByteArray(32 * 1024)
            sftp.open(clean, EnumSet.of(OpenMode.READ)).use { remote ->
                while (offset < total) {
                    if (cancelled()) throw CancellationException("Download cancelled")
                    val count = remote.read(offset, buffer, 0, minOf(buffer.size.toLong(), total - offset).toInt())
                    if (count <= 0) throw IOException("Remote file ended before expected size")
                    output.write(buffer, 0, count)
                    offset += count
                    progress(offset, total)
                }
            }
            output.flush()
            if (cancelled()) throw CancellationException("Download cancelled")
        }
    }

    /** Writes to a private temporary remote file, then renames it after all bytes arrive. */
    fun upload(directory: String, name: String, input: InputStream, cancelled: () -> Boolean = { false },
               progress: (Long) -> Unit = {}) {
        checked {
            val target = RemotePath.child(directory, name)
            if (sftp.statExistence(target) != null) throw IOException("Remote file already exists")
            val temporary = RemotePath.child(directory, ".sovagrid-upload-${UUID.randomUUID()}.part")
            var renamed = false
            try {
                val privateMode = FileAttributes.Builder().withPermissions(0x180).build() // 0600
                sftp.open(temporary, EnumSet.of(OpenMode.WRITE, OpenMode.CREAT, OpenMode.EXCL), privateMode).use { remote ->
                    val buffer = ByteArray(32 * 1024)
                    var offset = 0L
                    var zeroReads = 0
                    while (true) {
                        if (cancelled()) throw CancellationException("Upload cancelled")
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0) {
                            if (++zeroReads >= 3) throw IOException("Local document returned no bytes")
                            continue
                        }
                        zeroReads = 0
                        remote.write(offset, buffer, 0, count)
                        offset += count
                        progress(offset)
                    }
                }
                if (cancelled()) throw CancellationException("Upload cancelled")
                if (sftp.statExistence(target) != null) throw IOException("Remote file already exists")
                sftp.rename(temporary, target)
                renamed = true
            } finally {
                if (!renamed) runCatching { sftp.rm(temporary) }
            }
        }
    }

    private fun <T> checked(action: () -> T): T {
        check(isOpen) { "SFTP connection is closed" }
        return action()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { client.disconnect() }
        runCatching { sftp.close() }
        runCatching { channel?.close() }
        runCatching { gateway?.disconnect() }
    }
}
