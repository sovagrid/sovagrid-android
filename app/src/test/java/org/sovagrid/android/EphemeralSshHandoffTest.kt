/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class EphemeralSshHandoffTest {
    @Test fun copiedLoginSurvivesSshjClearingOriginalAndIsErasedAfterHandoff() {
        val original = SessionSshCredential.Password(charArrayOf('p', 'a', 's', 's'))
        val reusable = original.duplicate() as SessionSshCredential.Password
        original.clear()
        assertArrayEquals(charArrayOf('\u0000', '\u0000', '\u0000', '\u0000'), original.chars)
        assertArrayEquals(charArrayOf('p', 'a', 's', 's'), reusable.chars)
        SessionSshHandoff("server-id", reusable, null).clear()
        assertArrayEquals(charArrayOf('\u0000', '\u0000', '\u0000', '\u0000'), reusable.chars)
    }

    @Test fun clearingJumpHandoffErasesBothPasswords() {
        val target = SessionSshCredential.Password(charArrayOf('t'))
        val gateway = SessionSshCredential.Password(charArrayOf('g'))
        SessionSshHandoff("server-id", target, gateway).clear()
        assertArrayEquals(charArrayOf('\u0000'), target.chars)
        assertArrayEquals(charArrayOf('\u0000'), gateway.chars)
    }
}
