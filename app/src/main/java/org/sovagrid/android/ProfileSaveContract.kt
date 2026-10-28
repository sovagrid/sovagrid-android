/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.util.Base64

/** The only data accepted from the panel's one-use native profile bridge. */
internal data class ProfileSaveRequest(val filename: String, val bytes: ByteArray)

internal object ProfileSaveContract {
    private val filename = Regex("[a-z][a-z0-9-]{1,31}-[a-z][a-z0-9_-]{0,31}\\.conf")
    private val base64Url = Regex("[A-Za-z0-9_-]+")

    fun decode(version: Any?, suggestedName: Any?, encoded: Any?): ProfileSaveRequest? {
        if (version !is Int || version != 1 || suggestedName !is String ||
            !filename.matches(suggestedName) || encoded !is String ||
            encoded.length > 21_846 || !base64Url.matches(encoded)) return null
        val bytes = try { Base64.getUrlDecoder().decode(encoded) } catch (_: IllegalArgumentException) { return null }
        if (bytes.size !in 1..16_384 ||
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) != encoded) {
            bytes.fill(0)
            return null
        }
        return ProfileSaveRequest(suggestedName, bytes)
    }
}
