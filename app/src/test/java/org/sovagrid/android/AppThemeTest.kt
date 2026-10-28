/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppThemeTest {
    @Test fun unknownPreferenceUsesSystemMode() {
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromKey(null))
        assertEquals(ThemeMode.SYSTEM, ThemeMode.fromKey("unknown"))
        assertEquals(ThemeMode.LIGHT, ThemeMode.fromKey("light"))
        assertEquals(ThemeMode.DARK, ThemeMode.fromKey("dark"))
    }

    @Test fun explicitChoiceOverridesSystem() {
        assertFalse(AppTheme.isDark(ThemeMode.SYSTEM, false))
        assertTrue(AppTheme.isDark(ThemeMode.SYSTEM, true))
        assertFalse(AppTheme.isDark(ThemeMode.LIGHT, true))
        assertTrue(AppTheme.isDark(ThemeMode.DARK, false))
    }
}
