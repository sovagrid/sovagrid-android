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
import java.net.HttpURLConnection
import java.net.URI
import java.net.Socket
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import net.schmizz.sshj.SSHClient

/** Optional fixture with two independent SSH listeners, keys and credentials. */
class PanelJumpIntegrationTest {
    private data class Fixture(
        val gateway: Endpoint, val home: Endpoint,
        val gatewayPem: String, val homePem: String
    ) {
        fun gatewayAuth() = Authentication.PrivateKey(gatewayPem, charArrayOf())
        fun homeAuth() = Authentication.PrivateKey(homePem, charArrayOf())
    }

    private fun fixture(): Fixture {
        val names = listOf(
            "SOVAGRID_TEST_PANEL_GATEWAY_PORT", "SOVAGRID_TEST_PANEL_HOME_PORT",
            "SOVAGRID_TEST_PANEL_USER", "SOVAGRID_TEST_PANEL_GATEWAY_KEY_PATH",
            "SOVAGRID_TEST_PANEL_HOME_KEY_PATH"
        )
        assumeTrue(names.all { !System.getenv(it).isNullOrBlank() }, "Two-hop local SSH fixture unavailable")
        fun setting(name: String) = requireNotNull(System.getenv(name))
        val user = setting("SOVAGRID_TEST_PANEL_USER")
        return Fixture(
            Endpoint("127.0.0.1", setting("SOVAGRID_TEST_PANEL_GATEWAY_PORT").toInt(), user),
            Endpoint("127.0.0.1", setting("SOVAGRID_TEST_PANEL_HOME_PORT").toInt(), user),
            Files.readString(Path.of(setting("SOVAGRID_TEST_PANEL_GATEWAY_KEY_PATH"))),
            Files.readString(Path.of(setting("SOVAGRID_TEST_PANEL_HOME_KEY_PATH")))
        )
    }

    private fun assertFixturePanel(panel: LocalForwardConnection) {
        val response = URI("http://127.0.0.1:${panel.localPort}/sovagrid/monitoring/").toURL().openConnection() as HttpURLConnection
        response.connectTimeout = 5_000
        response.readTimeout = 5_000
        try {
            assertEquals(200, response.responseCode)
            assertTrue(response.inputStream.bufferedReader().use { it.readText() }.contains("SOVAGRID_HOME_PANEL_FIXTURE"))
        } finally {
            response.disconnect()
        }
    }

    @Test fun vpsRouteRemainsDirectAndBootstrapUsesVps() {
        val f = fixture()
        val core = SshClientCore()
        val gatewayPin = core.probe(f.gateway).wireBase64
        core.openHubPanel(f.gateway, gatewayPin, f.gatewayAuth()).use { panel ->
            assertFixturePanel(panel)
            val password = panel.readBootstrapPassword()
            try {
                assertArrayEquals("VpsFixturePassword_0123456789".toCharArray(), password)
            } finally {
                password.fill('\u0000')
            }
        }
    }

    @Test fun fullPanelAndBootstrapComeFromVerifiedHome() {
        val f = fixture()
        val core = SshClientCore()
        val gatewayPin = core.probe(f.gateway).wireBase64
        val homePin = core.probe(f.home, JumpHost(f.gateway, gatewayPin, f.gatewayAuth())).wireBase64
        assertTrue(gatewayPin != homePin, "The fixture must use distinct host keys")

        val panel = core.openHubPanel(f.home, homePin, f.homeAuth(),
            JumpHost(f.gateway, gatewayPin, f.gatewayAuth()))
        val localPort = panel.localPort
        fun sshConnection(name: String): SSHClient {
            val field = LocalForwardConnection::class.java.getDeclaredField(name)
            field.isAccessible = true
            return field.get(panel) as SSHClient
        }
        val homeConnection = sshConnection("client")
        val gatewayConnection = sshConnection("gateway")
        panel.use {
            assertFixturePanel(panel)
            val password = panel.readBootstrapPassword()
            try {
                assertArrayEquals("FixturePassword_0123456789".toCharArray(), password)
            } finally {
                password.fill('\u0000')
            }
        }
        assertFalse(panel.isOpen)
        assertFalse(homeConnection.isConnected)
        assertFalse(gatewayConnection.isConnected)
        assertThrows(IOException::class.java) {
            Socket("127.0.0.1", localPort).use { }
        }
    }

    @Test fun changedKeyAtEitherHopBlocksPanel() {
        val f = fixture()
        val core = SshClientCore()
        val gatewayPin = core.probe(f.gateway).wireBase64
        val homePin = core.probe(f.home, JumpHost(f.gateway, gatewayPin, f.gatewayAuth())).wireBase64
        fun changed(wire: String): String {
            val bytes = Base64.getDecoder().decode(wire)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            return Base64.getEncoder().encodeToString(bytes)
        }

        val gatewayError = assertThrows(HostKeyChangedException::class.java) {
            core.openHubPanel(f.home, homePin, f.homeAuth(),
                JumpHost(f.gateway, changed(gatewayPin), f.gatewayAuth()))
        }
        assertEquals(f.gateway, gatewayError.endpoint)

        val homeError = assertThrows(HostKeyChangedException::class.java) {
            core.openHubPanel(f.home, changed(homePin), f.homeAuth(),
                JumpHost(f.gateway, gatewayPin, f.gatewayAuth()))
        }
        assertEquals(f.home, homeError.endpoint)
    }
}
