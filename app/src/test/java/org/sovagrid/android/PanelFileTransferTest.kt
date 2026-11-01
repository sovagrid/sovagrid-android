/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

class PanelFileTransferTest {
    private val id = "a".repeat(32)
    private fun message(op: String, vararg fields: Pair<String, Any?>) =
        PanelFileMessage.decode(mapOf("op" to op, "id" to id) + fields.toMap())
    private fun fails(body: () -> Unit) {
        try { body(); fail("Expected rejection") } catch (_: IllegalStateException) { }
    }
    @Test fun boundedGrammarRejectsPathsAndNoncanonicalNumbersOrData() {
        listOf("archive.tar.gz", ".env", "ключ.pub").forEach { assertTrue(PanelFileContract.safeFilename(it)) }
        listOf("", ".", "..", "../secret", "a/b", "a\\b", "x:y", " x", "x\n", "я".repeat(121))
            .forEach { assertFalse(PanelFileContract.safeFilename(it)) }
        assertNotNull(message("start", "filename" to "archive.tar.gz"))
        assertNull(message("start", "filename" to "../secret"))
        assertNotNull(message("metadata", "bytes" to null))
        listOf(true, -1, 1.5, "10", PanelFileContract.MAX_BYTES + 1).forEach {
            assertNull(message("metadata", "bytes" to it))
        }
        assertArrayEquals(byteArrayOf(65), message("chunk", "index" to 0, "data" to "QQ==")!!.data)
        assertNull(message("chunk", "index" to true, "data" to "QQ=="))
        assertNull(message("chunk", "index" to 0, "data" to "QR=="))
        assertNull(message("chunk", "index" to 0, "data" to Base64.getEncoder().encodeToString(ByteArray(65537))))
        assertNull(message("cancel", "extra" to true))
    }
    @Test fun privateStreamingIsOrderedBoundedAndRequiresExactLength() {
        val base = Files.createTempDirectory("sovagrid-native-file-test").toFile()
        try {
            val download = PanelDownloadFile(id, "archive.bin", base)
            download.accept(message("metadata", "bytes" to 3)!!)
            download.accept(message("chunk", "index" to 0, "data" to "AAEC")!!)
            fails { download.accept(message("chunk", "index" to 0, "data" to "Aw==")!!) }
            download.accept(message("complete", "bytes" to 3)!!)
            assertTrue(download.complete)
            assertArrayEquals(byteArrayOf(0, 1, 2), download.file.readBytes())
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(download.file.toPath()))
            fails { download.accept(message("complete", "bytes" to 3)!!) }
            download.close(); assertFalse(download.directory.exists())
            val partial = PanelDownloadFile(id, "partial.bin", base, limit = 2)
            fails { partial.accept(message("chunk", "index" to 0, "data" to "AA==")!!) }
            fails { partial.accept(message("metadata", "bytes" to 3)!!) }
            partial.accept(message("metadata", "bytes" to 2)!!)
            partial.accept(message("chunk", "index" to 0, "data" to "AA==")!!)
            fails { partial.accept(message("complete", "bytes" to 1)!!) }
            fails { partial.accept(message("chunk", "index" to 1, "data" to "AAE=")!!) }
            partial.close(); assertFalse(partial.directory.exists())
        } finally { base.deleteRecursively() }
    }
    @Test fun uploadsArePrivateSnapshotsAndOversizeLeavesNoPartialFile() {
        val base = Files.createTempDirectory("sovagrid-native-upload-test").toFile()
        try {
            val source = byteArrayOf(0, 1, 2, -1)
            val upload = PanelUploadFile(ByteArrayInputStream(source), "key.pem", base)
            assertArrayEquals(source, upload.file.readBytes())
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(upload.file.toPath()))
            upload.close(); assertEquals(0, base.listFiles()!!.size)
            fails { PanelUploadFile(ByteArrayInputStream(ByteArray(PanelFileContract.UPLOAD_BYTES + 1)), "large.bin", base) }
            assertEquals(0, base.listFiles()!!.size)
        } finally { base.deleteRecursively() }
    }
}
