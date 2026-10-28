/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Run with scripts/test-terminal-local.sh against an isolated local sshd. */
class TerminalPtyIntegrationTest {
    @Test fun shellUsesVtPtyAndCanResizeAndSendRawKeys() {
        val host = System.getenv("SOVAGRID_TEST_PTY_SSH_HOST")
        val port = System.getenv("SOVAGRID_TEST_PTY_SSH_PORT")?.toIntOrNull()
        val user = System.getenv("SOVAGRID_TEST_PTY_SSH_USER")
        val key = System.getenv("SOVAGRID_TEST_PTY_SSH_KEY_PATH")
        assumeTrue(!host.isNullOrBlank() && port != null && !user.isNullOrBlank() && !key.isNullOrBlank())

        val endpoint = Endpoint(host!!, port!!, user!!)
        val core = SshClientCore()
        val pin = core.probe(endpoint).wireBase64
        val received = StringBuilder()
        val initial = CountDownLatch(1)
        val resized = CountDownLatch(1)
        val rawReady = CountDownLatch(1)
        val keySeen = CountDownLatch(1)
        val shell = core.openShell(endpoint, pin,
            Authentication.PrivateKey(Files.readString(Path.of(key!!)), charArrayOf()),
            onOutput = { chunk ->
                synchronized(received) {
                    received.append(chunk)
                    if ("29 83" in received) initial.countDown()
                    if ("17 47" in received) resized.countDown()
                    if ("RAW_" in received) rawReady.countDown()
                    if ("RAW_27" in received) keySeen.countDown()
                }
            }, onClosed = {}, columns = 83, rows = 29)
        shell.use {
            it.sendLine("stty size")
            assertTrue(initial.await(10, TimeUnit.SECONDS), "Initial PTY dimensions not reported")
            it.resize(47, 17)
            it.sendLine("stty size")
            assertTrue(resized.await(10, TimeUnit.SECONDS), "Window change not propagated")
            it.sendLine("stty raw -echo; printf '\\122\\101\\127\\137'; od -An -tu1 -N1 | tr -d ' '; stty sane")
            assertTrue(rawReady.await(10, TimeUnit.SECONDS), "Raw input fixture did not start")
            it.sendInput("\u001b")
            // Different od implementations may retain spaces; the byte itself must be visible.
            assertTrue(keySeen.await(10, TimeUnit.SECONDS), "Raw ESC key not delivered")
        }
    }
}
