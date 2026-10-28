/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.content.Context
import android.content.res.Configuration

enum class ThemeMode(val key: String, val label: String) {
    SYSTEM("system", "Системная"),
    LIGHT("light", "Светлая"),
    DARK("dark", "Тёмная");

    companion object {
        fun fromKey(key: String?): ThemeMode = entries.firstOrNull { it.key == key } ?: SYSTEM
    }
}

object AppTheme {
    private const val PREFERENCES = "appearance"
    private const val MODE = "theme_mode"

    fun mode(context: Context): ThemeMode = ThemeMode.fromKey(
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getString(MODE, null)
    )

    fun choose(context: Context, mode: ThemeMode) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putString(MODE, mode.key).apply()
    }

    fun isDark(context: Context): Boolean = isDark(
        mode(context),
        (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
    )

    internal fun isDark(mode: ThemeMode, systemDark: Boolean): Boolean = when (mode) {
        ThemeMode.SYSTEM -> systemDark
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }

    fun apply(activity: Activity) {
        activity.setTheme(if (isDark(activity)) R.style.Theme_SovaGrid_Dark else R.style.Theme_SovaGrid_Light)
    }
}
