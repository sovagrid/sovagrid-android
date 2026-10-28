/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Every timestamp in these models is a UTC Unix epoch second. */
internal data class HubClock(
    val systemUtcEpoch: Long,
    val timezone: String?,
    val ntpSynchronized: Boolean?,
    val rtcLocalTime: Boolean?,
    val rtcUtcEpoch: Long?,
    val rtcOffsetSeconds: Long?
)

internal data class HubCheckResult(
    val observedAt: Long,
    val receivedAt: Long,
    val status: String,
    val latencyMs: Int,
    val httpStatus: Int?,
    val tlsExpiresAt: Long?,
    val errorCode: String?
)

/** Deliberately excludes target URLs, hostnames, ports, leases, and credentials. */
internal data class HubCheck(
    val id: String,
    val name: String,
    val kind: String,
    val enabled: Boolean,
    val intervalSeconds: Int,
    val timeoutSeconds: Int,
    val state: String,
    val latest: HubCheckResult?
)

internal data class HubChecksSummary(
    val serverId: String,
    val revision: Long,
    val workerSeenAt: Long?,
    val checks: List<HubCheck>
)

internal object HubMonitoring {
    private const val MAX_EPOCH = 253_402_300_799L
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val zoneName = Regex("[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+){0,4}")
    private val incidentKinds = setOf("high_cpu", "high_memory", "high_disk", "high_root_inodes",
        "high_psi_cpu_some", "high_psi_memory_some", "high_psi_memory_full", "high_psi_io_some",
        "high_psi_io_full", "high_cpu_iowait", "high_cpu_steal", "failed_services", "offline")
    private val incidentHash = Regex("[0-9a-f]{64}")
    private val checkStates = setOf("disabled", "waiting", "up", "down", "stale")
    private val errorCodes = setOf("dns_error", "dns_mismatch", "connect_error", "tls_error", "timeout", "http_error", "invalid_response", "internal_error")
    private val dnsErrors = setOf("dns_error", "dns_mismatch", "timeout", "internal_error")

    fun epoch(value: Any?): Long? = integer(value)?.takeIf { it in 1..MAX_EPOCH }

    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }

    private fun number(value: Any?): Double? = when (value) {
        is Number -> value.toDouble().takeIf { it.isFinite() }
        else -> null
    }

    private fun name(value: Any?, maximum: Int): String? = (value as? String)?.takeIf {
        it.isNotBlank() && it.codePointCount(0, it.length) <= maximum && it == it.trim() &&
            it.codePoints().allMatch { code ->
                Character.getType(code) !in setOf(
                    Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.SURROGATE.toInt(),
                    Character.PRIVATE_USE.toInt(), Character.UNASSIGNED.toInt(), Character.LINE_SEPARATOR.toInt(),
                    Character.PARAGRAPH_SEPARATOR.toInt()
                )
            }
    }

    fun parseClock(fields: Map<String, Any?>?): HubClock? {
        if (fields == null) return null
        val system = epoch(fields["system_utc_epoch"]) ?: return null
        val timezone = (fields["timezone"] as? String)?.takeIf { it.length <= 64 && zoneName.matches(it) }
        val ntp = fields["ntp_synchronized"] as? Boolean
        val rtcLocal = fields["rtc_local_time"] as? Boolean
        val rtc = epoch(fields["rtc_utc_epoch"])
        val offset = integer(fields["rtc_offset_seconds"])?.takeIf { it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() }
        if ((rtc == null) != (offset == null) || (rtc != null && (rtcLocal != false || rtc - system != offset))) return null
        return HubClock(system, timezone, ntp, rtcLocal, rtc, offset)
    }

    fun parseServer(fields: Map<String, Any?>, latest: Map<String, Any?>?, clock: Map<String, Any?>?): HubServer? {
        val id = (fields["id"] as? String)?.takeIf(uuid::matches) ?: return null
        val accessRole = if (fields.containsKey("access_role")) {
            HubRole.entries.singleOrNull { it.wireName == fields["access_role"] } ?: return null
        } else null
        val cpu = number(latest?.get("cpu_percent"))?.takeIf { it in 0.0..100.0 }
        val memory = number(latest?.get("memory_percent"))?.takeIf { it in 0.0..100.0 }
        val disk = number(latest?.get("disk_percent"))?.takeIf { it in 0.0..100.0 }
        return HubServer(
            id = id,
            name = name(fields["name"], 80) ?: "Сервер",
            accessRole = accessRole,
            online = fields["online"] == true,
            remoteCommandsEnabled = fields["remote_commands_enabled"] == true,
            lastSeen = epoch(fields["last_seen"]),
            collectedAt = epoch(latest?.get("collected_at")),
            cpuPercent = cpu,
            memoryPercent = memory,
            diskPercent = disk,
            uptimeSeconds = integer(latest?.get("uptime_seconds"))?.takeIf { it >= 0 },
            clock = parseClock(clock)
        )
    }

    fun parseIncident(fields: Map<String, Any?>): HubIncident? {
        val id = (fields["id"] as? String)?.takeIf(uuid::matches) ?: return null
        val serverId = (fields["server_id"] as? String)?.takeIf(uuid::matches) ?: return null
        val kind = (fields["kind"] as? String)?.takeIf {
            it in incidentKinds ||
                (it.startsWith("check:") && uuid.matches(it.removePrefix("check:"))) ||
                (it.startsWith("tls:") && uuid.matches(it.removePrefix("tls:"))) ||
                (it.startsWith("container:") && incidentHash.matches(it.removePrefix("container:"))) ||
                (it.startsWith("filesystem:space:") && incidentHash.matches(it.removePrefix("filesystem:space:"))) ||
                (it.startsWith("filesystem:inodes:") && incidentHash.matches(it.removePrefix("filesystem:inodes:")))
        } ?: return null
        val state = (fields["state"] as? String)?.takeIf { it == "firing" || it == "resolved" } ?: return null
        val opened = epoch(fields["opened_at"]) ?: return null
        val updated = epoch(fields["updated_at"]) ?: return null
        val resolved = epoch(fields["resolved_at"])
        val acknowledged = epoch(fields["acknowledged_at"])
        return HubIncident(
            id, serverId, name(fields["server_name"], 80) ?: "Сервер", kind, state, opened, updated,
            resolved, acknowledged, number(fields["current_value"]), number(fields["threshold"]),
            if (kind.startsWith("check:") || kind.startsWith("tls:")) name(fields["subject"], 80)
            else if (kind.startsWith("container:")) name(fields["subject"], 96)
            else if (kind.startsWith("filesystem:")) name(fields["subject"], 128)
            else null
        )
    }

    fun parseCheck(fields: Map<String, Any?>, latest: Map<String, Any?>?): HubCheck? {
        val id = (fields["id"] as? String)?.takeIf(uuid::matches) ?: return null
        val checkName = name(fields["name"], 80) ?: return null
        val kind = (fields["kind"] as? String)?.takeIf { it == "http" || it == "tcp" || it == "dns" } ?: return null
        val enabled = fields["enabled"] as? Boolean ?: return null
        val interval = integer(fields["interval_seconds"])?.takeIf { it in 60..3600 }?.toInt() ?: return null
        val timeout = integer(fields["timeout_seconds"])?.takeIf { it in 1..10 }?.toInt() ?: return null
        val state = (fields["state"] as? String)?.takeIf(checkStates::contains) ?: return null
        val result = if (latest == null) null else parseCheckResult(latest, kind) ?: return null
        return HubCheck(id, checkName, kind, enabled, interval, timeout, state, result)
    }

    private fun parseCheckResult(fields: Map<String, Any?>, kind: String): HubCheckResult? {
        if (!fields.keys.containsAll(setOf("observed_at", "received_at", "status", "latency_ms", "http_status", "tls_expires_at", "error_code"))) return null
        val observed = epoch(fields["observed_at"]) ?: return null
        val received = epoch(fields["received_at"]) ?: return null
        val status = (fields["status"] as? String)?.takeIf { it == "up" || it == "down" } ?: return null
        val latency = integer(fields["latency_ms"])?.takeIf { it in 0..10000 }?.toInt() ?: return null
        val http = integer(fields["http_status"])?.takeIf { it in 100..599 }?.toInt()
        val tls = epoch(fields["tls_expires_at"])
        val error = (fields["error_code"] as? String)?.takeIf(errorCodes::contains)
        if ((fields["http_status"] != null && http == null) || (fields["tls_expires_at"] != null && tls == null) ||
            (fields["error_code"] != null && error == null)) return null
        if ((status == "up") != (error == null)) return null
        if (kind == "tcp" && (http != null || tls != null || error in setOf("http_error", "tls_error"))) return null
        if (kind == "dns" && (http != null || tls != null || error != null && error !in dnsErrors)) return null
        if (kind != "dns" && error == "dns_mismatch") return null
        if (kind == "http" && status == "up" && (http == null || http !in 200..299)) return null
        if (error == "http_error" && (http == null || http in 200..299)) return null
        if (error in setOf("dns_error", "connect_error", "tls_error") && http != null) return null
        if (error == "tls_error" && tls != null) return null
        return HubCheckResult(observed, received, status, latency, http, tls, error)
    }

    fun parseChecksSummary(fields: Map<String, Any?>, expectedServerId: String, checks: List<HubCheck>): HubChecksSummary? {
        if (fields["server_id"] != expectedServerId || !uuid.matches(expectedServerId) ||
            checks.size > 16 || checks.map { it.id }.toSet().size != checks.size) return null
        val revision = integer(fields["revision"])?.takeIf { it >= 0 } ?: return null
        return HubChecksSummary(expectedServerId, revision, epoch(fields["worker_seen_at"]), checks)
    }

    fun incidentTitle(incident: HubIncident): String = when (incident.kind) {
        "high_cpu" -> "Высокая нагрузка CPU"
        "high_memory" -> "Мало свободной памяти"
        "high_disk" -> "Заканчивается место на диске"
        "high_root_inodes" -> "Заканчиваются inode корневого раздела"
        "high_psi_cpu_some" -> "CPU перегружен (PSI)"
        "high_psi_memory_some", "high_psi_memory_full" -> "Память перегружена (PSI)"
        "high_psi_io_some", "high_psi_io_full" -> "Диск перегружен (PSI)"
        "high_cpu_iowait" -> "Высокое ожидание диска"
        "high_cpu_steal" -> "Высокий CPU steal"
        "failed_services" -> "Сбой системных служб"
        "offline" -> "Нет связи с сервером"
        else -> when {
            incident.kind.startsWith("filesystem:space:") ->
                (if (incident.state == "resolved") "Место восстановилось" else "Мало места") +
                    (incident.subject?.let { " · $it" } ?: " на файловой системе")
            incident.kind.startsWith("filesystem:inodes:") ->
                (if (incident.state == "resolved") "Inode восстановились" else "Заканчиваются inode") +
                    (incident.subject?.let { " · $it" } ?: " на файловой системе")
            incident.kind.startsWith("container:") ->
                (if (incident.state == "resolved") "Контейнер восстановился" else "Проблема контейнера") +
                    (incident.subject?.let { " · $it" } ?: "")
            incident.kind.startsWith("tls:") ->
                (if (incident.state == "resolved") "Сертификат TLS обновлён" else "Истекает сертификат TLS") +
                    (incident.subject?.let { " · $it" } ?: "")
            incident.state == "resolved" && incident.subject != null -> "Проверка восстановлена: «${incident.subject}»"
            incident.state == "resolved" -> "Сетевая проверка восстановлена"
            incident.subject != null -> "Недоступна проверка «${incident.subject}»"
            else -> "Недоступна сетевая проверка"
        }
    }

    fun checkState(state: String): String = when (state) {
        "up" -> "Работает"
        "down" -> "Недоступна"
        "waiting" -> "Ожидает первого результата"
        "stale" -> "Нет свежих данных"
        "disabled" -> "Отключена"
        else -> "Неизвестно"
    }

    fun checkKind(kind: String): String = when (kind) {
        "http" -> "HTTP/HTTPS"
        "tcp" -> "TCP"
        "dns" -> "DNS"
        else -> "Неизвестно"
    }

    fun checkError(code: String?): String = when (code) {
        "dns_error" -> "Ошибка DNS"
        "dns_mismatch" -> "Ответ DNS не соответствует ожидаемому"
        "connect_error" -> "Ошибка соединения"
        "tls_error" -> "Ошибка TLS"
        "timeout" -> "Превышено время ожидания"
        "http_error" -> "Ответ HTTP вне диапазона 2xx"
        "invalid_response" -> "Некорректный ответ"
        "internal_error" -> "Ошибка проверки"
        else -> ""
    }

    /** Format only at the UI boundary; the model never stores a local-clock-adjusted timestamp. */
    fun localStamp(epochSeconds: Long?, zone: ZoneId = ZoneId.systemDefault()): String {
        if (epochSeconds == null || epochSeconds !in 1..MAX_EPOCH) return "—"
        val instant = Instant.ofEpochSecond(epochSeconds)
        val date = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss", Locale.getDefault()).withZone(zone).format(instant)
        val offset = zone.rules.getOffset(instant)
        val offsetLabel = if (offset.totalSeconds == 0) "+00:00" else offset.id
        return "$date UTC$offsetLabel"
    }

    fun rtcOffset(clock: HubClock): String = when {
        clock.rtcOffsetSeconds != null -> {
            val value = clock.rtcOffsetSeconds
            "RTC относительно системных часов: ${if (value >= 0) "+" else ""}$value с. Это не отклонение от точного UTC."
        }
        clock.rtcLocalTime == true -> "RTC настроены на локальное время; отклонение от системных часов недоступно."
        else -> "Данные RTC недоступны."
    }
}
