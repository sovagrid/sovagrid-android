/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import net.schmizz.sshj.SSHClient
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import java.util.concurrent.TimeUnit

class DeviceSshKeyTest {
    @Test fun generatedPrivateKeyLoadsThroughTheSameSshjProviderAsAuthentication() {
        SshClientCore()
        val seed = DeviceSshKey.generateSeed()
        try {
            SSHClient().use { client ->
                val provider = client.loadKeys(DeviceSshKey.privateKey(seed), null, null)
                assertNotNull(provider.getPrivate())
                assertEquals(DeviceSshKey.publicKey(seed, "sovagrid-test").split(" ")[1],
                             HostKeySnapshot.from(provider.getPublic()).wireBase64)
            }
        } finally { seed.fill(0) }
    }

    @Test fun generatorProducesIndependentEd25519KeysAndOneLinePublicKey() {
        val first = DeviceSshKey.generateSeed()
        val second = DeviceSshKey.generateSeed()
        try {
            assertEquals(32, first.size)
            assertFalse(first.contentEquals(second))
            val line = DeviceSshKey.publicKey(first, "sovagrid-android-test")
            assertTrue(line.startsWith("ssh-ed25519 "))
            assertEquals(3, line.split(" ").size)
            assertEquals(51, Base64.getDecoder().decode(line.split(" ")[1]).size)
            assertFalse(line.contains('\n'))
            assertThrows(IllegalArgumentException::class.java) { DeviceSshKey.publicKey(first, "bad\ncomment") }
        } finally { first.fill(0); second.fill(0) }
    }

    @Test fun generatedPrivateKeyIsAcceptedByIndependentOpenSshAndMatchesPublicKey() {
        assumeTrue(!System.getProperty("os.name").startsWith("Windows"))
        val directory = Files.createTempDirectory("sovagrid-key-test-")
        val file = directory.resolve("key")
        val seed = DeviceSshKey.generateSeed()
        try {
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.writeString(file, DeviceSshKey.privateKey(seed))
            val process = try { ProcessBuilder("ssh-keygen", "-y", "-P", "", "-f", file.toString()).start() }
                catch (_: java.io.IOException) { assumeTrue(false, "ssh-keygen is not installed"); return }
            val exited = process.waitFor(10, TimeUnit.SECONDS)
            if (!exited) process.destroyForcibly()
            assertTrue(exited)
            assertEquals(0, process.exitValue())
            val observed = process.inputStream.bufferedReader().readText().trim().split(" ").take(2)
            val expected = DeviceSshKey.publicKey(seed, "sovagrid-android-test").split(" ").take(2)
            assertEquals(expected, observed)
        } finally { seed.fill(0); Files.deleteIfExists(file); Files.deleteIfExists(directory) }
    }
}
