/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SshGrantProtocolTest {
    private val grant = "A".repeat(43)
    private val valid = mapOf<String, Any?>(
        "protocol" to 1, "grant" to grant, "expires_at" to 1_800_000_000L, "username" to "admin"
    )

    @Test fun acceptsOnlyExactOneTimeResponse() {
        assertEquals(grant, SshGrantProtocol.validate(valid))
        assertNull(SshGrantProtocol.validate(valid + ("extra" to "value")))
        for (bad in listOf("A".repeat(42), "A".repeat(44), "A".repeat(42) + "/", "A".repeat(42) + "\n")) {
            assertNull(SshGrantProtocol.validate(valid + ("grant" to bad)))
        }
        assertNull(SshGrantProtocol.validate(valid + ("protocol" to "1")))
        assertNull(SshGrantProtocol.validate(valid + ("expires_at" to "1800000000")))
        assertNull(SshGrantProtocol.validate(valid + ("username" to "admin\nrole")))
    }
}
