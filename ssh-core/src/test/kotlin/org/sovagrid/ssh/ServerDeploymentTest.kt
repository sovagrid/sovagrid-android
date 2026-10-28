/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets

class ServerDeploymentTest {
    private fun parse(text: String, exit: Int? = 0): ServerDeployment {
        val bytes = text.toByteArray(StandardCharsets.US_ASCII)
        return ServerDeployment.parse(bytes, bytes.size, exit)
    }

    @Test fun exactVersionedStatesOnly() {
        val expected = mapOf(
            "managed" to ServerDeployment.MANAGED,
            "agent_only" to ServerDeployment.AGENT_ONLY,
            "missing" to ServerDeployment.MISSING,
            "conflict" to ServerDeployment.CONFLICT,
            "unsupported" to ServerDeployment.UNSUPPORTED,
            "unknown" to ServerDeployment.UNKNOWN,
        )
        for ((state, value) in expected) assertEquals(value, parse("SG_STATUS_V1:$state\n"))
        for (value in listOf("missing", "SG_STATUS_V2:missing\n", "SG_STATUS_V1:missing\nmanaged\n",
            "SG_STATUS_V1:missing\r\n", "SG_STATUS_V1:missing ", "SG_STATUS_V1:other\n")) {
            assertEquals(ServerDeployment.UNKNOWN, parse(value))
        }
        assertEquals(ServerDeployment.UNKNOWN, parse("SG_STATUS_V1:missing\n", exit = 1))
        assertEquals(ServerDeployment.UNKNOWN, parse("SG_STATUS_V1:missing\n", exit = null))
        assertEquals(ServerDeployment.UNKNOWN, parse("A".repeat(65)))
    }

    @Test fun fixedCommandDoesNotInterpolateProfileAndRequiresAuthority() {
        val command = ServerDeploymentProbe.READ_COMMAND
        assertTrue(command.contains("SG_STATUS_V1:"))
        assertTrue(command.contains("sudo -n /bin/sh -c"))
        assertTrue(command.contains("/var/lib/sovagrid/.managed-by-run-sh"))
        assertTrue(command.contains("/var/lib/sovagrid-first-install"))
        assertTrue(command.contains("/run/systemd/system"))
        assertFalse(command.contains("curl"))
        assertFalse(command.contains("wget"))
        assertFalse(command.contains("run.sh"))
        val grantCommand = SshGrantCommand.READ_COMMAND
        assertTrue(grantCommand.contains("sudo -n docker compose"))
        assertTrue(grantCommand.contains("--entrypoint python3 hub -m sovagrid_hub --db /data/hub.sqlite ssh-grant"))
        assertFalse(grantCommand.contains("curl"))
        assertFalse(grantCommand.contains("password"))
    }
}
