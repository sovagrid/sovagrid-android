/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.net.URI

/** A narrow escape hatch for Telegram setup links shown by the trusted Hub panel. */
internal object TelegramLinkPolicy {
    private val usernamePattern = Regex("[A-Za-z0-9_]{5,32}")

    fun externalUrl(raw: String): String? {
        val uri = try { URI(raw) } catch (_: Exception) { return null }
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            !uri.host.equals("t.me", ignoreCase = true) ||
            uri.rawUserInfo != null || uri.port != -1 ||
            uri.rawQuery != null || uri.rawFragment != null) return null

        val path = uri.rawPath ?: return null
        if (!path.startsWith('/') || path.indexOf('/', 1) != -1) return null
        val username = path.substring(1)
        if (!usernamePattern.matches(username) ||
            (!username.equals("BotFather", ignoreCase = true) &&
                !username.endsWith("bot", ignoreCase = true))) return null
        return "https://t.me/$username"
    }
}
