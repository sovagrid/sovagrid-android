/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** CI executes the exact commands compiled into Android, never a copied shell fixture. */
class ServerBootstrapCiExportTest {
    @Test fun exportFixedCommandsForEphemeralUbuntuRunner() {
        val directory = System.getenv("SOVAGRID_CI_INSTALL_COMMAND_DIR") ?: return
        val root = Path.of(directory)
        assertTrue(Files.isDirectory(root), "CI must create a private output directory")
        val start = ServerBootstrap.START_COMMAND
        val status = ServerBootstrap.STATUS_COMMAND
        assertTrue(start.contains(ServerBootstrap.EXPECTED_SOURCE_SHA256))
        assertTrue(start.contains(ServerBootstrap.EXPECTED_MANIFEST_SHA256))
        assertEquals(0, ProcessBuilder("/bin/bash", "-n", "-c", start).start().waitFor())
        assertEquals(0, ProcessBuilder("/bin/sh", "-n", "-c", status).start().waitFor())
        for ((name, command) in listOf("start.command" to start, "status.command" to status)) {
            val target = root.resolve(name)
            Files.writeString(target, command, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        }
    }
}
