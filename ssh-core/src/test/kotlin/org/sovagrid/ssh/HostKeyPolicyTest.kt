/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.Base64

class HostKeyPolicyTest {
    private fun key(vararg bytes: Byte) = Base64.getEncoder().encodeToString(bytes)

    @Test fun newHostRequiresConfirmation() {
        assertEquals(PinDecision.NEW, HostKeyPolicy.assess(null, key(1, 2, 3)))
    }

    @Test fun exactKeyCanConnect() {
        assertEquals(PinDecision.TRUSTED, HostKeyPolicy.assess(key(1, 2, 3), key(1, 2, 3)))
    }

    @Test fun changedOrCorruptPinBlocksConnection() {
        assertEquals(PinDecision.CHANGED, HostKeyPolicy.assess(key(1, 2, 3), key(1, 2, 4)))
        assertEquals(PinDecision.CHANGED, HostKeyPolicy.assess("corrupt", key(1, 2, 3)))
    }

    @Test fun pinnedAlgorithmIsReadFromSshWireFormat() {
        val name = "ssh-ed25519".toByteArray()
        val wire = byteArrayOf(0, 0, 0, name.size.toByte()) + name
        assertEquals("ssh-ed25519", HostKeySnapshot.algorithmFromWire(Base64.getEncoder().encodeToString(wire)))
    }
}
