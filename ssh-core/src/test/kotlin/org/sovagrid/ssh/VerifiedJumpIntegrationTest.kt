/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Optional integration test for a user-provided SSH target reached through a verified jump host. */
class VerifiedJumpIntegrationTest {
    @Test fun targetShellThroughVerifiedJumpHost() {
        val names = listOf(
            "SOVAGRID_TEST_JUMP_HOST",
            "SOVAGRID_TEST_JUMP_PORT",
            "SOVAGRID_TEST_JUMP_USER",
            "SOVAGRID_TEST_JUMP_KEY_PATH",
            "SOVAGRID_TEST_JUMP_FINGERPRINT",
            "SOVAGRID_TEST_TARGET_HOST",
            "SOVAGRID_TEST_TARGET_PORT",
            "SOVAGRID_TEST_TARGET_USER",
            "SOVAGRID_TEST_TARGET_KEY_PATH",
            "SOVAGRID_TEST_TARGET_FINGERPRINT"
        )
        assumeTrue(names.all { !System.getenv(it).isNullOrBlank() }, "Optional SSH test settings are not configured")

        fun setting(name: String) = requireNotNull(System.getenv(name))
        val gateway = Endpoint(
            setting("SOVAGRID_TEST_JUMP_HOST"),
            setting("SOVAGRID_TEST_JUMP_PORT").toInt(),
            setting("SOVAGRID_TEST_JUMP_USER")
        )
        val target = Endpoint(setting("SOVAGRID_TEST_TARGET_HOST"), setting("SOVAGRID_TEST_TARGET_PORT").toInt(), setting("SOVAGRID_TEST_TARGET_USER"))
        val gatewayPem = Files.readString(Path.of(setting("SOVAGRID_TEST_JUMP_KEY_PATH")))
        val targetPem = Files.readString(Path.of(setting("SOVAGRID_TEST_TARGET_KEY_PATH")))
        fun gatewayAuth() = Authentication.PrivateKey(gatewayPem, charArrayOf())
        fun targetAuth() = Authentication.PrivateKey(targetPem, charArrayOf())

        val core = SshClientCore()
        val gatewayKey = core.probe(gateway)
        // Compare against fingerprints obtained independently before sending either key.
        assertEquals(setting("SOVAGRID_TEST_JUMP_FINGERPRINT"), gatewayKey.fingerprintSha256)
        val targetKey = core.probe(target, JumpHost(gateway, gatewayKey.wireBase64, gatewayAuth()))
        assertEquals(setting("SOVAGRID_TEST_TARGET_FINGERPRINT"), targetKey.fingerprintSha256)

        val response = StringBuilder()
        val completed = CountDownLatch(1)
        core.openShell(
            target,
            targetKey.wireBase64,
            targetAuth(),
            onOutput = { chunk ->
                synchronized(response) {
                    response.append(chunk)
                    if ("SOVAGRID_TARGET_JUMP_OK" in response) completed.countDown()
                }
            },
            onClosed = {},
            jump = JumpHost(gateway, gatewayKey.wireBase64, gatewayAuth())
        ).use { shell ->
            // The command echo lacks the full marker; only executed output can satisfy this.
            shell.sendLine("printf 'SOVAGRID_%s\\n' TARGET_JUMP_OK")
            assertTrue(completed.await(10, TimeUnit.SECONDS), "No command output from target through jump host")
        }
    }
}
