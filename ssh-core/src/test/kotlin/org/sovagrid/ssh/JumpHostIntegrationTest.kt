/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.net.HttpURLConnection
import java.net.URI
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Optional live test: gateway forwards to its own loopback SSH listener, like a reverse tunnel. */
class JumpHostIntegrationTest {
    @Test fun sshSessionThroughVerifiedGateway() {
        val gatewayHost = System.getenv("SOVAGRID_TEST_SSH_HOST")
        val username = System.getenv("SOVAGRID_TEST_SSH_USER")
        val keyPath = System.getenv("SOVAGRID_TEST_SSH_KEY_PATH")
        assumeTrue(!gatewayHost.isNullOrBlank() && !username.isNullOrBlank() && !keyPath.isNullOrBlank())

        val core = SshClientCore()
        val gateway = Endpoint(gatewayHost!!, 22, username!!)
        val target = Endpoint("127.0.0.1", 22, username)
        val gatewayKey = core.probe(gateway)
        val pem = Files.readString(Path.of(keyPath!!))
        fun auth() = Authentication.PrivateKey(pem, charArrayOf())

        val targetKey = core.probe(target, JumpHost(gateway, gatewayKey.wireBase64, auth()))
        assertEquals(gatewayKey.wireBase64, targetKey.wireBase64)

        val received = StringBuilder()
        val done = CountDownLatch(1)
        val shell = core.openShell(target, targetKey.wireBase64, auth(),
            onOutput = { chunk ->
                synchronized(received) {
                    received.append(chunk)
                    if ("SOVAGRID_JUMP_OK" in received) done.countDown()
                }
            },
            onClosed = {},
            jump = JumpHost(gateway, gatewayKey.wireBase64, auth()))
        shell.use {
            it.sendLine("printf 'SOVAGRID_JUMP_OK\\n'")
            assertTrue(done.await(10, TimeUnit.SECONDS), "No shell response through jump host")
        }
    }

    @Test fun hubPanelIsReachableOnlyThroughLocalSshForward() {
        val gatewayHost = System.getenv("SOVAGRID_TEST_SSH_HOST")
        val username = System.getenv("SOVAGRID_TEST_SSH_USER")
        val keyPath = System.getenv("SOVAGRID_TEST_SSH_KEY_PATH")
        assumeTrue(!gatewayHost.isNullOrBlank() && !username.isNullOrBlank() && !keyPath.isNullOrBlank())

        val core = SshClientCore()
        val gateway = Endpoint(gatewayHost!!, 22, username!!)
        val hostKey = core.probe(gateway)
        val pem = Files.readString(Path.of(keyPath!!))
        core.openHubPanel(gateway, hostKey.wireBase64, Authentication.PrivateKey(pem, charArrayOf())).use { tunnel ->
            val response = URI("http://127.0.0.1:${tunnel.localPort}/").toURL().openConnection() as HttpURLConnection
            response.connectTimeout = 5_000
            response.readTimeout = 5_000
            try {
                assertEquals(200, response.responseCode)
                assertTrue(response.inputStream.bufferedReader().use { it.readText() }.contains("SovaGrid"))
            } finally {
                response.disconnect()
            }
        }
    }

    @Test fun changedKeyOnEitherHopBlocksAuthentication() {
        val gatewayHost = System.getenv("SOVAGRID_TEST_SSH_HOST")
        val username = System.getenv("SOVAGRID_TEST_SSH_USER")
        val keyPath = System.getenv("SOVAGRID_TEST_SSH_KEY_PATH")
        assumeTrue(!gatewayHost.isNullOrBlank() && !username.isNullOrBlank() && !keyPath.isNullOrBlank())

        val core = SshClientCore()
        val gateway = Endpoint(gatewayHost!!, 22, username!!)
        val target = Endpoint("127.0.0.1", 22, username)
        val gatewayKey = core.probe(gateway)
        val pem = Files.readString(Path.of(keyPath!!))
        fun auth() = Authentication.PrivateKey(pem, charArrayOf())
        fun changed(wire: String): String {
            val bytes = Base64.getDecoder().decode(wire)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            return Base64.getEncoder().encodeToString(bytes)
        }

        val gatewayError = assertThrows(HostKeyChangedException::class.java) {
            core.probe(target, JumpHost(gateway, changed(gatewayKey.wireBase64), auth()))
        }
        assertEquals(gateway, gatewayError.endpoint)

        val targetKey = core.probe(target, JumpHost(gateway, gatewayKey.wireBase64, auth()))
        val targetError = assertThrows(HostKeyChangedException::class.java) {
            core.openShell(target, changed(targetKey.wireBase64), auth(),
                onOutput = {}, onClosed = {}, jump = JumpHost(gateway, gatewayKey.wireBase64, auth()))
        }
        assertEquals(target, targetError.endpoint)
    }
}
