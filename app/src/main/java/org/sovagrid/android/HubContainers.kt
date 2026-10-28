/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

/** Fixed Docker actions; neither the UI nor the API accepts a shell command here. */
internal enum class HubContainerAction(val wireName: String, val label: String) {
    STATUS("status", "Проверить"),
    START("start", "Запустить"),
    STOP("stop", "Остановить"),
    RESTART("restart", "Перезапустить")
}

internal data class HubContainer(
    val id: String, val name: String, val image: String, val state: String,
    val health: String?, val restarts: Int?, val cpuPercent: Double?, val memoryBytes: Long?
)

internal data class HubContainerSource(
    val engine: String, val sourceStatus: String, val truncated: Boolean,
    val containers: List<HubContainer>
) {
    val complete: Boolean get() = engine == "docker" && sourceStatus == "ok" && !truncated
}

internal data class HubContainerInventory(val collectedAt: Long, val docker: HubContainerSource)

internal data class HubContainerControl(
    val sourceStatus: String, val id: String, val observedAt: Long?, val state: String?
)

internal data class HubContainerResult(
    val action: HubContainerAction, val id: String, val result: String, val state: String?
)

internal data class HubContainerJob(
    val id: String, val serverId: String, val state: String, val exitCode: Int?,
    val result: HubContainerResult?
) {
    val terminal: Boolean get() = state in setOf("succeeded", "failed", "timed_out", "output_limited", "cancelled")
}

internal object HubContainers {
    private val ident = Regex("[0-9a-f]{64}")
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val states = setOf("created", "running", "paused", "restarting", "removing", "exited", "dead")
    private val healthStates = setOf("starting", "healthy", "unhealthy")
    private val jobStates = setOf("queued", "delivered", "succeeded", "failed", "timed_out", "output_limited", "cancelled")

    fun validId(value: String): Boolean = ident.matches(value)
    fun validKey(value: String): Boolean = uuid.matches(value)

    /** Mirrors Hub's obvious infrastructure-name protection for local action gating. */
    fun protected(container: HubContainer): Boolean {
        fun forbidden(value: String): Boolean {
            val part = value.lowercase(java.util.Locale.ROOT).trimStart('/')
            return listOf("sovagrid", "amnezia", "docker", "containerd", "wireguard",
                "openvpn", "tailscale", "xray", "sing-box", "ssh").any(part::startsWith) ||
                "tunnel" in part
        }
        val imageParts = container.image.split('/').toMutableList()
        if (imageParts.size > 1 && ('.' in imageParts[0] || ':' in imageParts[0] || imageParts[0] == "localhost"))
            imageParts.removeAt(0)
        return forbidden(container.name) || imageParts.any { forbidden(it.substringBefore(':').substringBefore('@')) }
    }

    fun canCheck(server: HubServer, session: HubSession, container: HubContainer): Boolean =
        session.canAdminister(server.id) && server.online && server.remoteCommandsEnabled &&
            server.containers?.docker?.let { it.complete && it.containers.any { item -> item.id == container.id && item == container } } == true &&
            !protected(container)

    fun canMutate(server: HubServer, session: HubSession, container: HubContainer,
                  control: HubContainerControl?, ageMillis: Long): Boolean =
        canCheck(server, session, container) && control?.sourceStatus == "ok" &&
            control.id == container.id && control.state in states && ageMillis in 0 until 85_000

    fun parseInventory(fields: Map<String, Any?>): HubContainerInventory? {
        if (fields.keys != setOf("version", "collected_at", "engines") || fields["version"] != 1) return null
        val stamp = integer(fields["collected_at"])?.takeIf { it in 1..253_402_300_799 } ?: return null
        val engines = fields["engines"] as? List<*> ?: return null
        if (engines.size != 2) return null
        val docker = parseSource(engines[0], "docker") ?: return null
        if (parseSource(engines[1], "podman") == null) return null
        return HubContainerInventory(stamp, docker)
    }

    private fun parseSource(raw: Any?, expectedEngine: String): HubContainerSource? {
        val fields = raw as? Map<*, *> ?: return null
        if (fields.keys != setOf("engine", "source_status", "reason", "truncated", "containers") ||
            fields["engine"] != expectedEngine) return null
        val source = fields["source_status"] as? String ?: return null
        if (source !in setOf("ok", "unavailable") ||
            fields["reason"] !in setOf(null, "no_socket", "no_access", "error") ||
            (source == "ok") != (fields["reason"] == null)) return null
        val truncated = fields["truncated"] as? Boolean ?: return null
        val items = fields["containers"] as? List<*> ?: return null
        if (items.size > 12 || source == "unavailable" && (truncated || items.isNotEmpty())) return null
        val parsed = items.map { parseContainer(it) ?: return null }
        if (parsed.map { it.id }.toSet().size != parsed.size) return null
        return HubContainerSource(expectedEngine, source, truncated, parsed)
    }

    private fun parseContainer(raw: Any?): HubContainer? {
        val fields = raw as? Map<*, *> ?: return null
        if (fields.keys != setOf("id", "name", "image", "state", "health", "restarts", "cpu_percent", "memory_bytes")) return null
        val id = fields["id"] as? String ?: return null
        val name = fields["name"] as? String ?: return null
        val image = fields["image"] as? String ?: return null
        val state = fields["state"] as? String ?: return null
        if (!validId(id) || name.length !in 1..96 || image.length !in 1..160 ||
            name.any { it.isISOControl() } || image.any { it.isISOControl() } ||
            state !in states + "unknown") return null
        val health = fields["health"] as? String
        if (fields["health"] != null && health !in healthStates) return null
        val restarts = integer(fields["restarts"])
        if (fields["restarts"] != null && (restarts == null || restarts !in 0..Int.MAX_VALUE)) return null
        val cpu = (fields["cpu_percent"] as? Number)?.toDouble()
        if (fields["cpu_percent"] != null && (cpu == null || !cpu.isFinite() || cpu !in 0.0..10_000.0)) return null
        val memory = integer(fields["memory_bytes"])
        if (fields["memory_bytes"] != null && (memory == null || memory < 0)) return null
        return HubContainer(id, name, image, state, health, restarts?.toInt(), cpu, memory)
    }

    fun parseControl(fields: Map<String, Any?>, expectedId: String): HubContainerControl? {
        if (!validId(expectedId) || fields.keys != setOf("source_status", "engine", "id", "observed_at", "state") ||
            fields["engine"] != "docker" || fields["id"] != expectedId) return null
        val source = fields["source_status"] as? String ?: return null
        val observed = integer(fields["observed_at"])
        val state = fields["state"] as? String
        if (source == "unavailable" && observed == null && state == null)
            return HubContainerControl(source, expectedId, null, null)
        if (source != "ok" || observed == null || observed <= 0 || state !in states) return null
        return HubContainerControl(source, expectedId, observed, state)
    }

    fun parseResult(fields: Map<String, Any?>, expectedAction: HubContainerAction,
                    expectedId: String): HubContainerResult? {
        if (fields.keys != setOf("action", "id", "result", "state") ||
            fields["action"] != expectedAction.wireName || fields["id"] != expectedId || !validId(expectedId)) return null
        val result = fields["result"] as? String ?: return null
        val state = fields["state"] as? String
        if (result !in setOf("ok", "failed", "uncertain") || state != null && state !in states ||
            result == "ok" && (state == null || expectedAction == HubContainerAction.STOP && state != "exited" ||
                expectedAction in setOf(HubContainerAction.START, HubContainerAction.RESTART) && state != "running")) return null
        return HubContainerResult(expectedAction, expectedId, result, state)
    }

    fun parseJob(fields: Map<String, Any?>, expectedServerId: String,
                 result: HubContainerResult? = null): HubContainerJob? {
        val id = fields["id"] as? String ?: return null
        val serverId = fields["server_id"] as? String ?: return null
        val state = fields["state"] as? String ?: return null
        if (!validKey(id) || !validKey(serverId) || serverId != expectedServerId || state !in jobStates) return null
        val exit = integer(fields["exit_code"])
        if (fields["exit_code"] != null && (exit == null || exit !in Int.MIN_VALUE..Int.MAX_VALUE)) return null
        return HubContainerJob(id, serverId, state, exit?.toInt(), result)
    }

    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }
}
