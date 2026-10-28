/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TerminalKeysTest {
    @Test fun mapsCommonControlKeys() {
        assertEquals("\u0003", TerminalKeys.control("c"))
        assertEquals("\u0004", TerminalKeys.control("D"))
        assertEquals("\u001b", TerminalKeys.control("["))
        assertEquals("\u007f", TerminalKeys.control("?"))
    }

    @Test fun doesNotTransformPasteOrArrowSequence() {
        assertNull(TerminalKeys.control("paste"))
        assertNull(TerminalKeys.control("\u001b[A"))
        assertNull(TerminalKeys.control("ж"))
    }
}
