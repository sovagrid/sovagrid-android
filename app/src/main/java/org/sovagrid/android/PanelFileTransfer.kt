/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import java.util.UUID

internal object PanelFileContract {
    const val MAX_BYTES = 32L * 1024 * 1024 * 1024
    const val CHUNK_BYTES = 65536
    const val UPLOAD_BYTES = 4 * 1024 * 1024
    fun safeFilename(name: String): Boolean = name.isNotEmpty() && name !in listOf(".", "..") &&
        name.toByteArray(Charsets.UTF_8).size <= 240 && name == name.trim() &&
        name.none { it.isISOControl() || it in "/\\:" }
    fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }?.takeIf { it in 0..MAX_BYTES }
    fun privateDirectory(base: File): File {
        Files.createDirectories(base.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        return Files.createDirectory(File(base, UUID.randomUUID().toString().replace("-", "")).toPath(),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toFile()
    }
}

internal data class PanelFileMessage(val op: String, val id: String, val filename: String? = null,
    val index: Long? = null, val bytes: Long? = null, val data: ByteArray? = null) {
    val step: String get() = if (op == "chunk") index.toString() else op
    companion object {
        fun decode(fields: Map<String, Any?>): PanelFileMessage? {
            val op = fields["op"] as? String ?: return null
            val id = fields["id"] as? String ?: return null
            if (!Regex("[a-f0-9]{32}").matches(id)) return null
            val keys = when (op) {
                "start" -> setOf("op", "id", "filename")
                "metadata", "complete" -> setOf("op", "id", "bytes")
                "chunk" -> setOf("op", "id", "index", "data")
                "cancel" -> setOf("op", "id")
                else -> return null
            }
            if (fields.keys != keys) return null
            return when (op) {
                "start" -> (fields["filename"] as? String)?.takeIf(PanelFileContract::safeFilename)
                    ?.let { PanelFileMessage(op, id, filename = it) }
                "metadata" -> if (fields["bytes"] == null) PanelFileMessage(op, id)
                    else PanelFileContract.integer(fields["bytes"])?.let { PanelFileMessage(op, id, bytes = it) }
                "complete" -> PanelFileContract.integer(fields["bytes"])?.let { PanelFileMessage(op, id, bytes = it) }
                "chunk" -> {
                    val index = PanelFileContract.integer(fields["index"]) ?: return null
                    val encoded = fields["data"] as? String ?: return null
                    if (encoded.length > 87384) return null
                    val decoded = try { Base64.getDecoder().decode(encoded) } catch (_: IllegalArgumentException) { return null }
                    if (decoded.size !in 1..PanelFileContract.CHUNK_BYTES || Base64.getEncoder().encodeToString(decoded) != encoded) return null
                    PanelFileMessage(op, id, index = index, data = decoded)
                }
                else -> PanelFileMessage(op, id)
            }
        }
    }
}

internal class PanelDownloadFile(val id: String, val filename: String, base: File,
                                private val limit: Long = PanelFileContract.MAX_BYTES) : AutoCloseable {
    val directory: File
    val file: File
    private var output: FileOutputStream? = null
    private var metadata = false
    private var expected: Long? = null
    private var index = 0L
    var count = 0L; private set
    var complete = false; private set
    init {
        require(PanelFileContract.safeFilename(filename))
        directory = PanelFileContract.privateDirectory(base)
        file = File(directory, filename)
        try {
            Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            output = FileOutputStream(file)
        } catch (error: Exception) { directory.deleteRecursively(); throw error }
    }
    @Synchronized fun accept(message: PanelFileMessage) {
        check(message.id == id && !complete && output != null)
        when (message.op) {
            "metadata" -> {
                check(!metadata && (message.bytes == null || message.bytes <= limit))
                metadata = true; expected = message.bytes
            }
            "chunk" -> {
                val chunk = message.data ?: error("Missing chunk")
                check(metadata && message.index == index && chunk.size in 1..PanelFileContract.CHUNK_BYTES && chunk.size <= limit - count &&
                    (expected == null || count + chunk.size <= expected!!))
                output!!.write(chunk); count += chunk.size; index++
            }
            "complete" -> {
                check(metadata && message.bytes == count && (expected == null || count == expected))
                output!!.fd.sync(); output!!.close(); output = null; complete = true
            }
            else -> error("Unexpected operation")
        }
    }
    @Synchronized override fun close() {
        try { output?.close() } catch (_: Exception) { }
        output = null; directory.deleteRecursively()
    }
}

internal class PanelUploadFile(source: InputStream, filename: String, base: File) : AutoCloseable {
    val directory = PanelFileContract.privateDirectory(base)
    val file = File(directory, filename)
    init {
        try {
            require(PanelFileContract.safeFilename(filename))
            Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            FileOutputStream(file).use { output ->
                val buffer = ByteArray(65536)
                var count = 0
                while (true) {
                    val n = source.read(buffer)
                    if (n < 0) break
                    check(n <= PanelFileContract.UPLOAD_BYTES - count)
                    output.write(buffer, 0, n); count += n
                }
                buffer.fill(0); output.fd.sync()
            }
        } catch (error: Exception) { directory.deleteRecursively(); throw error }
    }
    override fun close() { directory.deleteRecursively() }
}
