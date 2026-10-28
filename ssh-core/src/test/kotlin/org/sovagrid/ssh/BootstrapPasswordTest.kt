/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.IOException
import java.nio.charset.StandardCharsets

class BootstrapPasswordTest {
    @Test fun acceptsInstallerFormatWithOptionalNewline() {
        val value = "AbcdefghijklmnopQRSTUV_0123456789-"
        for (suffix in listOf("", "\n", "\r\n")) {
            assertArrayEquals(value.toCharArray(), BootstrapPassword.parse((value + suffix).toByteArray(StandardCharsets.US_ASCII)))
        }
    }

    @Test fun rejectsUnexpectedOrUnboundedOutput() {
        val examples = listOf(
            "short\n", "A".repeat(129), "A".repeat(20) + "\n\n",
            "A".repeat(20) + " ", "A".repeat(20) + "é", "A".repeat(257),
            "A".repeat(20) + "\u0000"
        )
        for (value in examples) assertThrows(IOException::class.java) {
            BootstrapPassword.parse(value.toByteArray(StandardCharsets.UTF_8))
        }
    }

    @Test fun commandIsFixedAndBounded() {
        assertArrayEquals("head -c 257 /etc/sovagrid/admin-password".toCharArray(), BootstrapPassword.READ_COMMAND.toCharArray())
    }
}
