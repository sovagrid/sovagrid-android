/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

/** Service actions are a structured Hub protocol, never a shell command. */
internal enum class HubServiceAction(val wireName: String, val label: String) {
    STATUS("status", "Проверить"),
    START("start", "Запустить"),
    STOP("stop", "Остановить"),
    RESTART("restart", "Перезапустить")
}

internal data class HubServiceControl(
    val unit: String,
    val sourceStatus: String,
    val observedAt: Long?,
    val loadState: String?,
    val activeState: String?,
    val subState: String?
)

internal data class HubServiceResult(
    val action: HubServiceAction,
    val unit: String,
    val result: String,
    val loadState: String?,
    val activeState: String?,
    val subState: String?
)

internal data class HubServiceJob(
    val id: String,
    val serverId: String,
    val state: String,
    val exitCode: Int?,
    val result: HubServiceResult?
) {
    val terminal: Boolean get() = state in setOf("succeeded", "failed", "timed_out", "output_limited", "cancelled")
}

internal object HubServices {
    private val unit = Regex("[A-Za-z0-9][A-Za-z0-9_.@-]{0,87}\\.service")
    private val state = Regex("[a-z][a-z0-9-]{0,31}")
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val protectedBases = setOf(
        "ssh", "sshd", "dropbear", "dbus", "networking", "networkmanager", "network-manager",
        "docker", "containerd", "podman", "cri-o", "nftables", "ufw", "firewalld",
        "iptables", "netfilter-persistent", "caddy", "wg-quick", "awg-quick",
        "openvpn", "strongswan", "ipsec"
    )

    fun validUnit(value: String): Boolean = unit.matches(value) && !value.endsWith("@.service")

    fun protectedUnit(value: String): Boolean {
        if (!validUnit(value)) return false
        val base = value.removeSuffix(".service").lowercase(java.util.Locale.ROOT).substringBefore('@')
        return base in protectedBases || listOf("sovagrid", "systemd-", "amnezia", "autossh").any(base::startsWith) ||
            "tunnel" in base
    }

    fun canCheck(server: HubServer, session: HubSession): Boolean =
        session.canAdminister(server.id) && server.online && server.remoteCommandsEnabled

    fun canMutate(server: HubServer, session: HubSession, requestedUnit: String,
                  control: HubServiceControl?, ageMillis: Long): Boolean =
        canCheck(server, session) && validUnit(requestedUnit) && !protectedUnit(requestedUnit) &&
            control?.sourceStatus == "ok" && control.unit == requestedUnit && ageMillis in 0 until 85_000

    fun parseControl(fields: Map<String, Any?>, expectedUnit: String): HubServiceControl? {
        if (!validUnit(expectedUnit) || fields.keys != setOf(
                "source_status", "unit", "observed_at", "load_state", "active_state", "sub_state") ||
            fields["unit"] != expectedUnit) return null
        val source = fields["source_status"] as? String ?: return null
        val observed = integer(fields["observed_at"])
        val states = listOf("load_state", "active_state", "sub_state").map { fields[it] as? String }
        if (source == "unavailable" && observed == null && states.all { it == null })
            return HubServiceControl(expectedUnit, source, null, null, null, null)
        if (source != "ok" || observed == null || observed <= 0 || states.any { it == null || !state.matches(it) }) return null
        return HubServiceControl(expectedUnit, source, observed, states[0], states[1], states[2])
    }

    fun parseResult(fields: Map<String, Any?>): HubServiceResult? {
        if (fields.keys != setOf("action", "unit", "result", "load_state", "active_state", "sub_state")) return null
        val action = HubServiceAction.entries.singleOrNull { it.wireName == fields["action"] } ?: return null
        val name = fields["unit"] as? String ?: return null
        if (!validUnit(name)) return null
        val result = fields["result"] as? String ?: return null
        if (result !in setOf("ok", "failed", "uncertain")) return null
        val states = listOf("load_state", "active_state", "sub_state").map { fields[it] as? String }
        if (states.any { it != null && !state.matches(it) } ||
            (result == "ok" && states.any { it == null })) return null
        return HubServiceResult(action, name, result, states[0], states[1], states[2])
    }

    fun parseJob(fields: Map<String, Any?>, expectedServerId: String,
                 result: HubServiceResult? = null): HubServiceJob? {
        val id = fields["id"] as? String ?: return null
        val serverId = fields["server_id"] as? String ?: return null
        val jobState = fields["state"] as? String ?: return null
        if (!uuid.matches(id) || serverId != expectedServerId || !uuid.matches(serverId) ||
            jobState !in setOf("queued", "delivered", "succeeded", "failed", "timed_out", "output_limited", "cancelled")) return null
        val exit = integer(fields["exit_code"])
        if (fields["exit_code"] != null && (exit == null || exit !in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())) return null
        val exitCode = exit?.toInt()
        return HubServiceJob(id, serverId, jobState, exitCode, result)
    }

    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
}
