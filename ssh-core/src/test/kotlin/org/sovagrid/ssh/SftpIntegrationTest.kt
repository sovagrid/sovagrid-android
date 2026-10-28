/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Random
import java.util.concurrent.CancellationException

/** Runs against scripts/test-sftp-local.sh with a disposable local sshd and sftp-server. */
class SftpIntegrationTest {
    @Test fun binaryTransferNavigationCollisionAndCancellation() {
        val host = System.getenv("SOVAGRID_TEST_SFTP_HOST")
        val port = System.getenv("SOVAGRID_TEST_SFTP_PORT")?.toIntOrNull()
        val user = System.getenv("SOVAGRID_TEST_SFTP_USER")
        val key = System.getenv("SOVAGRID_TEST_SFTP_KEY_PATH")
        val remoteDir = System.getenv("SOVAGRID_TEST_SFTP_DIR")
        assumeTrue(!host.isNullOrBlank() && port != null && !user.isNullOrBlank() &&
            !key.isNullOrBlank() && !remoteDir.isNullOrBlank())
        val endpoint = Endpoint(host!!, port!!, user!!)
        val core = SshClientCore()
        val pin = core.probe(endpoint).wireBase64
        val wrongPin = core.probe(endpoint).wireBase64.dropLast(4) + "AAAA"
        assertThrows(HostKeyChangedException::class.java) {
            core.openFiles(endpoint, wrongPin, Authentication.PrivateKey(Files.readString(Path.of(key!!)), charArrayOf()))
        }
        val payload = ByteArray(256 * 1024 + 7).also(Random(42)::nextBytes)
        val client = core.openFiles(endpoint, pin, Authentication.PrivateKey(Files.readString(Path.of(key)), charArrayOf()))
        client.use { files ->
            assertTrue(files.home().startsWith("/"))
            assertTrue(files.list(remoteDir!!).isEmpty())
            files.upload(remoteDir, "binary.dat", ByteArrayInputStream(payload))
            val listing = files.list(remoteDir)
            assertTrue(listing.any { it.name == "binary.dat" && it.isFile && it.size == payload.size.toLong() })
            val copied = ByteArrayOutputStream()
            files.download(RemotePath.child(remoteDir, "binary.dat"), copied)
            assertArrayEquals(payload, copied.toByteArray())
            assertThrows(IOException::class.java) {
                files.upload(remoteDir, "binary.dat", ByteArrayInputStream(payload))
            }
            var sent = 0L
            assertThrows(CancellationException::class.java) {
                files.upload(remoteDir, "cancelled.dat", ByteArrayInputStream(payload),
                    cancelled = { sent > 0 }, progress = { sent = it })
            }
            assertTrue(sent > 0, "Cancellation happened after a partial remote write")
            assertFalse(files.list(remoteDir).any { it.name == "cancelled.dat" || it.name.startsWith(".sovagrid-upload-") })
            var received = 0L
            val partial = ByteArrayOutputStream()
            assertThrows(CancellationException::class.java) {
                files.download(RemotePath.child(remoteDir, "binary.dat"), partial,
                    cancelled = { received > 0 }, progress = { done, _ -> received = done })
            }
            assertTrue(partial.size() in 1 until payload.size)
            files.upload(remoteDir, "empty.dat", ByteArrayInputStream(byteArrayOf()))
            val empty = ByteArrayOutputStream()
            files.download(RemotePath.child(remoteDir, "empty.dat"), empty)
            assertEquals(0, empty.size())
        }
        // A second authenticated hop exercises the same direct-tcpip route used for gateway → target.
        val jump = JumpHost(endpoint, pin, Authentication.PrivateKey(Files.readString(Path.of(key)), charArrayOf()))
        val targetKey = core.probe(endpoint, jump)
        assertEquals(pin, targetKey.wireBase64, "Destination key is observed before destination authentication")
        assertThrows(HostKeyChangedException::class.java) {
            core.probe(endpoint, JumpHost(endpoint, wrongPin,
                Authentication.PrivateKey(Files.readString(Path.of(key)), charArrayOf())))
        }
        val authenticatedJump = JumpHost(endpoint, pin, Authentication.PrivateKey(Files.readString(Path.of(key)), charArrayOf()))
        core.openFiles(endpoint, pin, Authentication.PrivateKey(Files.readString(Path.of(key)), charArrayOf()), authenticatedJump).use { files ->
            files.upload(remoteDir, "jump.bin", ByteArrayInputStream(byteArrayOf(0, 1, -1)))
            val output = ByteArrayOutputStream()
            files.download(RemotePath.child(remoteDir, "jump.bin"), output)
            assertArrayEquals(byteArrayOf(0, 1, -1), output.toByteArray())
        }
    }
}
