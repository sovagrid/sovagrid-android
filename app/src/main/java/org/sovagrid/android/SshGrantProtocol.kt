/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.json.JSONObject

/** Validate the one-shot SSH CLI response before it enters the panel's JavaScript context. */
internal object SshGrantProtocol {
    private val GRANT = Regex("[A-Za-z0-9_-]{43}")
    private val FIELDS = setOf("protocol", "grant", "expires_at", "username")

    fun parse(raw: String): String? = try {
        val payload = JSONObject(raw)
        val keys = buildSet { val values = payload.keys(); while (values.hasNext()) add(values.next()) }
        if (keys != FIELDS) null
        else validate(keys.associateWith(payload::opt))
    } catch (_: Exception) { null }

    /** Separate pure validation keeps malformed metadata away from WebView injection. */
    fun validate(payload: Map<String, Any?>): String? {
        if (payload.keys != FIELDS || payload["protocol"] != 1) return null
        val grant = payload["grant"] as? String ?: return null
        val username = payload["username"] as? String ?: return null
        val expires = payload["expires_at"]
        if (!GRANT.matches(grant) || username.isEmpty() || username.codePointCount(0, username.length) > 80 ||
            username.any { Character.isISOControl(it) } ||
            (expires !is Int && expires !is Long) || (expires as Number).toLong() !in 1_000_000_000L..4_102_444_800L) {
            return null
        }
        return grant
    }
}
