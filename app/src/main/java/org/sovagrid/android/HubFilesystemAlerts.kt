/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.nio.charset.StandardCharsets

internal data class HubFilesystemRule(val mountpoint: String, val metric: String, val thresholdPercent: Int)
internal data class HubFilesystemMount(
    val mountpoint: String, val fstype: String, val spaceUsedPercent: Double?, val inodesUsedPercent: Double?
)
internal data class HubFilesystemObservation(
    val mountpoint: String, val metric: String, val status: String, val usedPercent: Double?
)
internal data class HubFilesystemAlertsState(
    val serverId: String, val revision: Long, val holdSeconds: Int, val rules: List<HubFilesystemRule>,
    val sourceStatus: String, val observedAt: Long?, val filesystems: List<HubFilesystemMount>,
    val observations: List<HubFilesystemObservation>
)

/** Strict, pure validation of the Hub's viewer-safe filesystem alert contract. */
internal object HubFilesystemAlerts {
    private val uuid = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    private val metrics = setOf("space", "inodes")
    private val sources = setOf("ok", "stale", "partial", "unavailable")
    private val states = setOf("normal", "alert", "unknown")
    private const val MAX_EPOCH = 253_402_300_799L

    fun validMountpoint(value: String): Boolean {
        if (!value.startsWith('/') || value.toByteArray(StandardCharsets.UTF_8).size !in 1..128 ||
            value.any { it.isISOControl() }) return false
        return value == "/" || value.substring(1).split('/').all { it.isNotEmpty() && it != "." && it != ".." }
    }

    fun validRule(rule: HubFilesystemRule): Boolean = validMountpoint(rule.mountpoint) &&
        rule.metric in metrics && rule.thresholdPercent in 1..100

    fun validProposal(rules: List<HubFilesystemRule>, holdSeconds: Int): Boolean =
        holdSeconds in 0..86400 && rules.size <= 32 && rules.all(::validRule) &&
            rules.map { it.mountpoint to it.metric }.toSet().size == rules.size

    fun available(state: HubFilesystemAlertsState, server: HubServer): List<Pair<String, String>> {
        if (state.serverId != server.id || !server.online || state.sourceStatus != "ok") return emptyList()
        return buildList {
            for (item in state.filesystems) {
                if (item.spaceUsedPercent != null) add(item.mountpoint to "space")
                if (item.inodesUsedPercent != null) add(item.mountpoint to "inodes")
            }
        }
    }

    fun parse(fields: Map<String, Any?>, expectedServerId: String): HubFilesystemAlertsState? {
        if (!uuid.matches(expectedServerId) || fields["server_id"] != expectedServerId ||
            !fields.keys.containsAll(setOf("server_id", "revision", "hold_seconds", "rules", "source_status",
                "observed_at", "filesystems", "observations"))) return null
        val revision = integer(fields["revision"])?.takeIf { it >= 0 } ?: return null
        val hold = integer(fields["hold_seconds"])?.takeIf { it in 0..86400 }?.toInt() ?: return null
        val source = (fields["source_status"] as? String)?.takeIf(sources::contains) ?: return null
        val observed = if (fields["observed_at"] == null) null else
            integer(fields["observed_at"])?.takeIf { it in 1..MAX_EPOCH } ?: return null
        val rawRules = fields["rules"] as? List<*> ?: return null
        val rawMounts = fields["filesystems"] as? List<*> ?: return null
        val rawObservations = fields["observations"] as? List<*> ?: return null
        if (rawRules.size > 32 || rawMounts.size > 16 || rawObservations.size != rawRules.size ||
            (source != "ok" && rawMounts.isNotEmpty())) return null
        val rules = rawRules.map { raw ->
            val item = raw as? Map<*, *> ?: return null
            if (item.keys != setOf("mountpoint", "metric", "threshold_percent")) return null
            val threshold = integer(item["threshold_percent"])?.takeIf { it in 1..100 }?.toInt() ?: return null
            HubFilesystemRule(item["mountpoint"] as? String ?: return null,
                item["metric"] as? String ?: return null, threshold)
        }
        if (!validProposal(rules, hold)) return null
        val mounts = rawMounts.map { raw ->
            val item = raw as? Map<*, *> ?: return null
            if (item.keys != setOf("mountpoint", "fstype", "space_used_percent", "inodes_used_percent")) return null
            val path = item["mountpoint"] as? String ?: return null
            val fstype = item["fstype"] as? String ?: return null
            if (!validMountpoint(path) || fstype.isBlank() || fstype.length > 32 || fstype.any { it.isISOControl() }) return null
            val space = percent(item["space_used_percent"])
            val inodes = percent(item["inodes_used_percent"])
            if (item["space_used_percent"] != null && space == null ||
                item["inodes_used_percent"] != null && inodes == null) return null
            HubFilesystemMount(path, fstype, space, inodes)
        }
        if (mounts.map { it.mountpoint }.toSet().size != mounts.size) return null
        val ruleIndex = rules.associateBy { it.mountpoint to it.metric }
        val observations = rawObservations.map { raw ->
            val item = raw as? Map<*, *> ?: return null
            if (item.keys != setOf("mountpoint", "metric", "status", "used_percent")) return null
            val path = item["mountpoint"] as? String ?: return null
            val metric = item["metric"] as? String ?: return null
            val rule = ruleIndex[path to metric] ?: return null
            val status = (item["status"] as? String)?.takeIf(states::contains) ?: return null
            val used = percent(item["used_percent"])
            if ((status == "unknown") != (item["used_percent"] == null) ||
                status != "unknown" && (used == null || (used >= rule.thresholdPercent) != (status == "alert"))) return null
            HubFilesystemObservation(path, metric, status, used)
        }
        if (observations.map { it.mountpoint to it.metric }.toSet().size != rules.size) return null
        return HubFilesystemAlertsState(expectedServerId, revision, hold, rules, source, observed, mounts, observations)
    }

    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }

    private fun percent(value: Any?): Double? {
        if (value == null) return null
        val number = when (value) {
            is Int -> value.toDouble()
            is Long -> value.toDouble()
            is Double -> value
            else -> return null
        }
        return number.takeIf { it.isFinite() && it in 0.0..100.0 }
    }
}
