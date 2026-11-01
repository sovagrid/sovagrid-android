/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.*
import org.junit.Test

class PanelRestoreContractTest {
    private val session = "a".repeat(32)
    private val id = "b".repeat(32)
    private val handle = "c".repeat(64)
    private fun message(action: String, vararg fields: Pair<String, Any?>) =
        PanelRestoreMessage.decode(mapOf("action" to action, "session" to session, "id" to id) + fields.toMap())

    @Test fun fixedActionsTokensAndExactFieldsAreRequired() {
        assertNotNull(message("pick")); assertNotNull(message("release"))
        for (action in listOf("open", "open-path", "write", "delete", "")) assertNull(message(action))
        assertNull(message("pick", "path" to "/private/file"))
        assertNull(message("release", "extra" to true))
        for (value in listOf("", "A".repeat(32), "a".repeat(31), "../secret", true, 42)) {
            assertNull(message("pick", "session" to value))
            assertNull(message("pick", "id" to value))
        }
        assertNull(message("read", "handle" to "guessable", "offset" to 0, "length" to 1))
        assertNull(message("read", "handle" to "C".repeat(64), "offset" to 0, "length" to 1))
    }

    @Test fun integerRangesRejectCoercionAndMoreThanOneIPCChunk() {
        assertNotNull(message("read", "handle" to handle, "offset" to 0, "length" to 262144))
        assertNotNull(message("read", "handle" to handle, "offset" to PanelRestoreContract.FILE_BYTES, "length" to 1))
        for (value in listOf(true, false, -1, 0.5, 1.0, "1", null, Long.MAX_VALUE, PanelRestoreContract.FILE_BYTES + 1))
            assertNull(message("read", "handle" to handle, "offset" to value, "length" to 1))
        for (value in listOf(true, false, -1, 0, 0.5, 1.0, "1", null, 262145, Long.MAX_VALUE))
            assertNull(message("read", "handle" to handle, "offset" to 0, "length" to value))
        assertNull(message("read", "handle" to handle, "offset" to 0, "length" to 1, "path" to "ignored"))
    }

    @Test fun descriptorSizeAndOffsetArithmeticCannotOverflowOrReadPastEOF() {
        assertTrue(PanelRestoreContract.range(10, 9, 1))
        assertTrue(PanelRestoreContract.range(PanelRestoreContract.FILE_BYTES, PanelRestoreContract.FILE_BYTES - 262144, 262144))
        for ((size, offset, length) in listOf(
            Triple(0L, 0L, 1L), Triple(10L, -1L, 1L), Triple(10L, 10L, 1L),
            Triple(10L, 9L, 2L), Triple(10L, 0L, 0L), Triple(10L, 0L, 262145L),
            Triple(PanelRestoreContract.FILE_BYTES + 1, 0L, 1L),
            Triple(10L, Long.MIN_VALUE, 1L), Triple(10L, Long.MAX_VALUE, 1L), Triple(10L, 0L, Long.MAX_VALUE)
        )) assertFalse(PanelRestoreContract.range(size, offset, length))
    }
}
