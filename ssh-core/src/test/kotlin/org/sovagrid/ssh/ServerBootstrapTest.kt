/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ServerBootstrapTest {
    private fun parse(line: String, exit: Int? = 0): FirstInstallJob {
        val bytes = line.toByteArray(Charsets.US_ASCII)
        return ServerBootstrap.parseStatus(bytes, bytes.size, exit)
    }

    @Test fun fixedDetachedInstallerIsDigestPinnedAndSyntaxValid() {
        val command = ServerBootstrap.START_COMMAND
        assertTrue(command.contains("systemd-run --quiet --collect --unit=sovagrid-first-install"))
        assertTrue(command.contains("v0.10.0-preview/SovaGrid-server-source-0.10.0-preview.tar.gz"))
        assertTrue(command.contains(ServerBootstrap.EXPECTED_SOURCE_SHA256))
        assertTrue(command.contains(ServerBootstrap.EXPECTED_MANIFEST_SHA256))
        assertTrue(command.contains("/run/sovagrid-first-install.lock"))
        assertTrue(command.contains("/var/lib/sovagrid-first-install"))
        assertTrue(command.contains("head -c 67108865"))
        assertEquals(0, ProcessBuilder("/bin/bash", "-n", "-c", command).start().waitFor())
        assertEquals(0, ProcessBuilder("/bin/sh", "-n", "-c", ServerBootstrap.STATUS_COMMAND).start().waitFor())
    }

    @Test fun parserAcceptsOnlyFixedPrivateJobStates() {
        assertEquals(FirstInstallState.NONE, parse("SG_INSTALL_JOB_V1:none\n").state)
        assertEquals(FirstInstallJob(FirstInstallState.RUNNING, "RUN"),
            parse("SG_INSTALL_JOB_V1:running:RUN:NONE\n"))
        assertEquals(FirstInstallJob(FirstInstallState.DONE, "DONE"),
            parse("SG_INSTALL_JOB_V1:done:DONE:NONE\n"))
        assertEquals(FirstInstallJob(FirstInstallState.FAILED, "RUN", "RESULT"),
            parse("SG_INSTALL_JOB_V1:failed:RUN:RESULT\n"))
        for (bad in listOf("SG_INSTALL_JOB_V1:none", "SG_INSTALL_JOB_V1:running:EVIL:NONE\n", "SG_INSTALL_JOB_V1:done:DONE:NONE\nmore",
            "SG_INSTALL_JOB_V1:failed:RUN:secret\n", "SG_INSTALL_JOB_V1:none\r\n")) {
            assertEquals(FirstInstallState.UNKNOWN, parse(bad).state)
        }
        assertEquals(FirstInstallState.UNKNOWN, parse("SG_INSTALL_JOB_V1:none\n", exit = 1).state)
    }
}
