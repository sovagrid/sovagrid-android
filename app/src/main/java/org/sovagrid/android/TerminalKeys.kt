/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

/** Ctrl combinations for the mobile keyboard's one-shot Ctrl button. */
internal object TerminalKeys {
    fun control(value: String): String? {
        if (value.length != 1) return null
        val char = value[0]
        val code = when (char) {
            in 'a'..'z' -> char.code - 'a'.code + 1
            in 'A'..'Z' -> char.code - 'A'.code + 1
            '@', ' ', '2' -> 0
            '[', '3' -> 27
            '\\', '4' -> 28
            ']', '5' -> 29
            '^', '6' -> 30
            '_', '7' -> 31
            '?', '8' -> 127
            else -> return null
        }
        return code.toChar().toString()
    }
}
