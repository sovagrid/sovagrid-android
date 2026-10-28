/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.io.IOException

/** Optional local SSH fixture can ForceCommand a fake password without touching /etc. */
class BootstrapPasswordSshIntegrationTest {
    @Test fun readsThroughVerifiedPanelConnection() {
        val host = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_HOST")
        val port = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_PORT")?.toIntOrNull()
        val user = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_USER")
        val key = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_KEY_PATH")
        assumeTrue(!host.isNullOrBlank() && port != null && !user.isNullOrBlank() && !key.isNullOrBlank())

        val core = SshClientCore()
        val endpoint = Endpoint(host!!, port!!, user!!)
        val pin = core.probe(endpoint).wireBase64
        val pem = Files.readString(Path.of(key!!))
        core.openHubPanel(endpoint, pin, Authentication.PrivateKey(pem, charArrayOf())).use { panel ->
            val password = panel.readBootstrapPassword()
            try {
                assertArrayEquals("FixturePassword_0123456789".toCharArray(), password)
            } finally {
                password.fill('\u0000')
            }
        }
    }

    @Test fun deniedRemoteCommandDoesNotReturnPassword() {
        val host = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_HOST")
        val port = System.getenv("SOVAGRID_TEST_BOOTSTRAP_DENIED_PORT")?.toIntOrNull()
        val user = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_USER")
        val key = System.getenv("SOVAGRID_TEST_BOOTSTRAP_SSH_KEY_PATH")
        assumeTrue(!host.isNullOrBlank() && port != null && !user.isNullOrBlank() && !key.isNullOrBlank())

        val core = SshClientCore()
        val endpoint = Endpoint(host!!, port!!, user!!)
        val pin = core.probe(endpoint).wireBase64
        val pem = Files.readString(Path.of(key!!))
        core.openHubPanel(endpoint, pin, Authentication.PrivateKey(pem, charArrayOf())).use { panel ->
            assertThrows(IOException::class.java) { panel.readBootstrapPassword() }
        }
    }
}
