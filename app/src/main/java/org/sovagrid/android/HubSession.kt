/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.io.IOException

internal enum class HubRole(val wireName: String, val label: String, val canAcknowledge: Boolean) {
    VIEWER("viewer", "Наблюдатель", false),
    OPERATOR("operator", "Оператор", true),
    ADMIN("admin", "Администратор", true)
}

internal data class HubIdentity(
    val id: String?,
    val username: String,
    val role: HubRole,
    val legacy: Boolean,
    val revision: Long? = null
)

internal data class HubAccess(val mode: String, val revision: Long, val unrestrictedAdmin: Boolean)

/** Kept only by the active screen; avoid leaking the bearer token through toString(). */
internal class HubSession(val token: String, val identity: HubIdentity, val expiresAt: Long?) {
    @Volatile private var effectiveRoles: Map<String, HubRole> = emptyMap()

    fun canAcknowledge(serverId: String): Boolean = effectiveRoles[serverId]?.canAcknowledge == true

    fun canAdminister(serverId: String): Boolean = effectiveRoles[serverId] == HubRole.ADMIN

    fun effectiveRole(serverId: String): HubRole? = effectiveRoles[serverId]

    fun updateAccess(access: HubAccess, servers: List<HubServer>) {
        val roles = buildMap {
            for (server in servers) {
                val reported = server.accessRole
                val role = when {
                    reported != null -> if (reported.ordinal <= identity.role.ordinal) reported else identity.role
                    access.mode == "all" -> identity.role // Older Hub summaries omit access_role.
                    else -> throw HubIdentityException() // A selected grant must be explicit.
                }
                put(server.id, role)
            }
        }
        if (roles.size != servers.size) throw HubIdentityException()
        effectiveRoles = roles
    }
    override fun toString(): String = "HubSession(identity=$identity, token=<redacted>)"
}

internal class HubIdentityException : IOException("Не удалось подтвердить учётную запись и права доступа Hub.")

/** Pure parsing/policy, independent of Android's permissive JSONObject getters. */
internal object HubSessionParser {
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val MAX_EPOCH_SECONDS = 253_402_300_799L

    fun login(payload: Map<String, Any?>, legacyUsername: String): HubSession {
        val token = payload["token"] as? String ?: invalid()
        if (token.isEmpty() || token.length > 4096 || token.any { it.code !in 0x21..0x7e }) invalid()
        val expiresAt = if (payload.containsKey("expires_at")) {
            integer(payload["expires_at"], MAX_EPOCH_SECONDS).also { if (it == 0L) invalid() }
        } else null
        val identity = if (payload.containsKey("user")) identity(payload["user"])
        else {
            if (!printable(legacyUsername, 80)) invalid()
            HubIdentity(null, legacyUsername, HubRole.ADMIN, legacy = true)
        }
        return HubSession(token, identity, expiresAt)
    }

    fun confirm(payload: Map<String, Any?>, expected: HubIdentity) {
        // Omitted identity is compatible only with an older login, never with a new Hub.
        if (expected.legacy || !payload.containsKey("user")) invalid()
        val current = identity(payload["user"])
        if (current.id != expected.id || current.username != expected.username || current.role != expected.role) invalid()
    }

    fun access(payload: Map<String, Any?>, identity: HubIdentity): HubAccess {
        val value = payload["access"] as? Map<*, *> ?: invalid()
        val mode = value["mode"] as? String ?: invalid()
        val revision = integer(value["revision"], MAX_SAFE_INTEGER)
        val unrestricted = value["unrestricted_admin"] as? Boolean ?: invalid()
        if (mode !in setOf("all", "selected") ||
            unrestricted != (mode == "all" && identity.role == HubRole.ADMIN)) invalid()
        return HubAccess(mode, revision, unrestricted)
    }

    fun legacyAccess(identity: HubIdentity): HubAccess = HubAccess(
        "all", 0, identity.role == HubRole.ADMIN
    )

    private fun identity(value: Any?): HubIdentity {
        val user = value as? Map<*, *> ?: invalid()
        val id = user["id"] as? String ?: invalid()
        val username = user["username"] as? String ?: invalid()
        val roleName = user["role"] as? String ?: invalid()
        val role = HubRole.entries.singleOrNull { it.wireName == roleName } ?: invalid()
        if (id.isEmpty() || id.length > 64 || id.any { it.code !in 0x21..0x7e } ||
            !printable(username, 80) || user["enabled"] != true) invalid()
        val revision = integer(user["revision"], MAX_SAFE_INTEGER)
        integer(user["created_at"], MAX_EPOCH_SECONDS)
        integer(user["updated_at"], MAX_EPOCH_SECONDS)
        return HubIdentity(id, username, role, legacy = false, revision = revision)
    }

    private fun integer(value: Any?, maximum: Long): Long {
        val number = when (value) {
            is Int -> value.toLong()
            is Long -> value
            else -> invalid()
        }
        if (number < 0 || number > maximum) invalid()
        return number
    }

    private fun printable(value: String, maximum: Int): Boolean {
        if (value.isEmpty() || value.codePointCount(0, value.length) > maximum || value != value.trim()) return false
        return value.codePoints().allMatch { code ->
            code == 0x20 || Character.getType(code) !in setOf(
                Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.SURROGATE.toInt(),
                Character.PRIVATE_USE.toInt(), Character.UNASSIGNED.toInt(), Character.LINE_SEPARATOR.toInt(),
                Character.PARAGRAPH_SEPARATOR.toInt(), Character.SPACE_SEPARATOR.toInt()
            )
        }
    }

    private fun invalid(): Nothing = throw HubIdentityException()
}
