/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.json.JSONObject
import org.json.JSONArray
import org.json.JSONException
import java.io.IOException
import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import javax.net.ssl.HttpsURLConnection

internal data class HubServer(
    val id: String,
    val name: String,
    val accessRole: HubRole?,
    val online: Boolean,
    val remoteCommandsEnabled: Boolean,
    val lastSeen: Long?,
    val collectedAt: Long?,
    val cpuPercent: Double?,
    val memoryPercent: Double?,
    val diskPercent: Double?,
    val uptimeSeconds: Long?,
    val clock: HubClock?,
    val containers: HubContainerInventory? = null
)

internal data class HubIncident(
    val id: String,
    val serverId: String,
    val serverName: String,
    val kind: String,
    val state: String,
    val openedAt: Long,
    val updatedAt: Long,
    val resolvedAt: Long?,
    val acknowledgedAt: Long?,
    val currentValue: Double?,
    val threshold: Double?,
    val subject: String?
)

internal data class HubSnapshot(val servers: List<HubServer>, val incidents: List<HubIncident>)

internal class HubHttpException(val statusCode: Int) : IOException("Hub HTTP $statusCode")

/** Hub credentials and token are passed in memory only; this class never persists them. */
internal class HubApi(address: String) {
    private val origin: String

    init {
        val uri = try {
            URI(address.trim())
        } catch (_: Exception) {
            throw IllegalArgumentException("Укажите HTTPS-адрес Hub")
        }
        require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
            "Для Hub нужен HTTPS-адрес"
        }
        require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
            (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") && uri.port in -1..65535 && uri.port != 0) {
            "Укажите адрес Hub без пути и параметров"
        }
        origin = URI("https", null, uri.host, uri.port, null, null, null).toASCIIString()
    }

    fun login(username: String, password: CharArray): HubSession {
        require(username.isNotBlank() && password.isNotEmpty()) { "Введите логин и пароль" }
        val body = JSONObject()
            .put("username", username)
            .put("password", String(password))
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
        try {
            val response = request("POST", "/api/v1/session", body = body)
            return HubSessionParser.login(JSONObject(response).sessionFields(), username)
        } finally {
            body.fill(0)
        }
    }

    fun servers(token: String): List<HubServer> {
        val array = JSONObject(request("GET", "/api/v1/servers", token = token)).getJSONArray("servers")
        val parsed = buildList {
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val latest = item.optJSONObject("latest")
                val clock = latest?.optJSONObject("details")?.optJSONObject("clock")
                val details = latest?.optJSONObject("details")
                val rawContainers = details?.opt("containers")
                val containers = if (rawContainers == null || rawContainers === JSONObject.NULL) null else {
                    val fields = (rawContainers as? JSONObject)?.plainFields() ?: throw HubIdentityException()
                    HubContainers.parseInventory(fields) ?: throw HubIdentityException()
                }
                HubMonitoring.parseServer(
                    item.fields("id", "name", "online", "last_seen", "access_role", "remote_commands_enabled"),
                    latest?.fields("collected_at", "cpu_percent", "memory_percent", "disk_percent", "uptime_seconds"),
                    clock?.fields("system_utc_epoch", "timezone", "ntp_synchronized", "rtc_local_time", "rtc_utc_epoch", "rtc_offset_seconds")
                )?.copy(containers = containers)?.let(::add)
            }
        }
        if (parsed.size != array.length()) throw HubIdentityException()
        return parsed
    }

    fun snapshot(session: HubSession): HubSnapshot {
        verifyIdentity(session)
        val access = if (session.identity.legacy) HubSessionParser.legacyAccess(session.identity)
            else try {
                val payload = JSONObject(request("GET", "/api/v1/session/access", token = session.token))
                HubSessionParser.access(mapOf("access" to payload.getJSONObject("access").fields(
                    "mode", "revision", "unrestricted_admin"
                )), session.identity)
            } catch (error: HubHttpException) {
                if (error.statusCode == 404) HubSessionParser.legacyAccess(session.identity) else throw error
            } catch (_: JSONException) {
                throw HubIdentityException()
            }
        val (servers, incidents) = try {
            servers(session.token) to incidents(session.token)
        } catch (_: JSONException) {
            throw HubIdentityException()
        }
        session.updateAccess(access, servers)
        return HubSnapshot(servers, incidents)
    }

    private fun verifyIdentity(session: HubSession) {
        if (!session.identity.legacy) {
            val response = request("GET", "/api/v1/session", token = session.token)
            val payload = try { JSONObject(response).sessionFields() }
                catch (_: JSONException) { throw HubIdentityException() }
            HubSessionParser.confirm(payload, session.identity)
        }
    }

    fun incidents(token: String): List<HubIncident> {
        val array = JSONObject(request("GET", "/api/v1/incidents", token = token)).getJSONArray("incidents")
        val parsed = buildList {
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                HubMonitoring.parseIncident(item.fields(
                    "id", "server_id", "server_name", "kind", "state", "opened_at", "updated_at",
                    "resolved_at", "acknowledged_at", "current_value", "threshold", "subject"
                ))?.let(::add)
            }
        }
        if (parsed.size != array.length()) throw HubIdentityException()
        return parsed
    }

    /** Viewer-safe check summary: targets and credentials are never requested or modeled. */
    fun checks(session: HubSession, serverId: String): HubChecksSummary {
        require(INCIDENT_ID.matches(serverId)) { "Неверный идентификатор сервера" }
        verifyIdentity(session)
        val response = JSONObject(request("GET", "/api/v1/servers/$serverId/checks", token = session.token))
        val array = response.getJSONArray("checks")
        val summaries = buildList {
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val latest = item.optJSONObject("latest")
                HubMonitoring.parseCheck(item.fields(
                    "id", "name", "kind", "enabled", "interval_seconds", "timeout_seconds", "state"
                ), latest?.fields(
                    "observed_at", "status", "latency_ms", "http_status", "tls_expires_at", "error_code", "received_at"
                ))?.let(::add)
            }
        }
        if (summaries.size != array.length()) throw IOException("Некорректный ответ проверок Hub")
        return HubMonitoring.parseChecksSummary(response.fields("server_id", "revision", "worker_seen_at"), serverId, summaries)
            ?: throw IOException("Некорректный ответ проверок Hub")
    }

    fun filesystemAlerts(session: HubSession, serverId: String): HubFilesystemAlertsState {
        require(INCIDENT_ID.matches(serverId)) { "Неверный идентификатор сервера" }
        verifyIdentity(session)
        val fields = JSONObject(request("GET", "/api/v1/servers/$serverId/filesystems/alerts",
            token = session.token)).plainFields()
        return HubFilesystemAlerts.parse(fields, serverId)
            ?: throw IOException("Hub прислал неверные правила дисковых тревог")
    }

    fun saveFilesystemAlerts(session: HubSession, current: HubFilesystemAlertsState,
                             rules: List<HubFilesystemRule>, holdSeconds: Int): HubFilesystemAlertsState {
        require(INCIDENT_ID.matches(current.serverId) && HubFilesystemAlerts.validProposal(rules, holdSeconds)) {
            "Неверные правила дисковых тревог"
        }
        if (!session.canAdminister(current.serverId)) throw HubIdentityException()
        verifyIdentity(session)
        val items = JSONArray()
        rules.forEach { rule -> items.put(JSONObject().put("mountpoint", rule.mountpoint)
            .put("metric", rule.metric).put("threshold_percent", rule.thresholdPercent)) }
        val body = JSONObject().put("revision", current.revision).put("hold_seconds", holdSeconds)
            .put("rules", items).toString().toByteArray(StandardCharsets.UTF_8)
        val fields = JSONObject(request("PUT", "/api/v1/servers/${current.serverId}/filesystems/alerts",
            token = session.token, body = body)).plainFields()
        val saved = HubFilesystemAlerts.parse(fields, current.serverId)
            ?: throw IOException("Hub прислал неверное подтверждение дисковых тревог")
        if (saved.revision != current.revision + 1 || saved.rules != rules || saved.holdSeconds != holdSeconds)
            throw IOException("Hub вернул другую ревизию дисковых тревог")
        return saved
    }

    fun acknowledge(session: HubSession, incidentId: String, serverId: String? = null) {
        require(INCIDENT_ID.matches(incidentId)) { "Неверный идентификатор события" }
        if (serverId == null || !INCIDENT_ID.matches(serverId) || !session.canAcknowledge(serverId))
            throw HubIdentityException()
        verifyIdentity(session)
        request("POST", "/api/v1/incidents/$incidentId/ack", token = session.token, body = "{}".toByteArray(StandardCharsets.UTF_8))
    }

    fun serviceControl(session: HubSession, serverId: String, unit: String): HubServiceControl {
        require(INCIDENT_ID.matches(serverId) && HubServices.validUnit(unit)) { "Неверная служба или сервер" }
        verifyIdentity(session)
        val escaped = URLEncoder.encode(unit, StandardCharsets.UTF_8.name())
        val value = JSONObject(request("GET", "/api/v1/servers/$serverId/services/control?unit=$escaped",
            token = session.token)).getJSONObject("control")
        return HubServices.parseControl(value.allFields(), unit)
            ?: throw IOException("Hub прислал неверное состояние службы")
    }

    fun queueServiceAction(session: HubSession, server: HubServer, action: HubServiceAction,
                           unit: String, key: String, control: HubServiceControl? = null,
                           controlAgeMillis: Long = Long.MAX_VALUE): HubServiceJob {
        require(INCIDENT_ID.matches(server.id) && HubServices.validUnit(unit) &&
            key == java.util.UUID.fromString(key).toString()) { "Неверная служба, сервер или ключ запроса" }
        if (!HubServices.canCheck(server, session) ||
            action != HubServiceAction.STATUS && !HubServices.canMutate(
                server, session, unit, control, controlAgeMillis)) throw HubIdentityException()
        verifyIdentity(session)
        val body = JSONObject().put("action", action.wireName).put("unit", unit).toString()
            .toByteArray(StandardCharsets.UTF_8)
        val value = JSONObject(request("POST", "/api/v1/servers/${server.id}/services/actions",
            token = session.token, body = body, idempotencyKey = key)).getJSONObject("job")
        return HubServices.parseJob(value.fields("id", "server_id", "state", "exit_code"), server.id)
            ?: throw IOException("Hub прислал неверное задание службы")
    }

    fun serviceJob(session: HubSession, serverId: String, jobId: String): HubServiceJob {
        require(INCIDENT_ID.matches(serverId) && INCIDENT_ID.matches(jobId)) { "Неверное задание службы" }
        if (!session.canAdminister(serverId)) throw HubIdentityException()
        val value = JSONObject(request("GET", "/api/v1/jobs/$jobId", token = session.token)).getJSONObject("job")
        val output = when (val raw = value.opt("output")) {
            null, JSONObject.NULL -> ""
            is String -> raw
            else -> throw IOException("Hub прислал неверный результат задания")
        }
        val result = try {
            if (output.toByteArray(StandardCharsets.UTF_8).size > 8192 || output.isBlank()) null else
                HubServices.parseResult(JSONObject(output).allFields())
        } catch (_: JSONException) { null }
        return HubServices.parseJob(value.fields("id", "server_id", "state", "exit_code"), serverId, result)
            ?.takeIf { it.id == jobId } ?: throw IOException("Hub прислал неверное задание службы")
    }

    fun containerControl(session: HubSession, serverId: String, id: String): HubContainerControl {
        require(INCIDENT_ID.matches(serverId) && HubContainers.validId(id)) { "Неверный контейнер или сервер" }
        verifyIdentity(session)
        val value = JSONObject(request("GET", "/api/v1/servers/$serverId/containers/control?engine=docker&id=$id",
            token = session.token)).getJSONObject("control")
        return HubContainers.parseControl(value.allFields(), id)
            ?: throw IOException("Hub прислал неверное состояние контейнера")
    }

    fun queueContainerAction(session: HubSession, server: HubServer, action: HubContainerAction,
                             container: HubContainer, key: String, control: HubContainerControl? = null,
                             controlAgeMillis: Long = Long.MAX_VALUE): HubContainerJob {
        require(INCIDENT_ID.matches(server.id) && HubContainers.validId(container.id) && HubContainers.validKey(key)) {
            "Неверный контейнер, сервер или ключ запроса"
        }
        if (!HubContainers.canCheck(server, session, container) ||
            action != HubContainerAction.STATUS && !HubContainers.canMutate(
                server, session, container, control, controlAgeMillis)) throw HubIdentityException()
        verifyIdentity(session)
        val body = JSONObject().put("action", action.wireName).put("engine", "docker")
            .put("id", container.id).toString().toByteArray(StandardCharsets.UTF_8)
        val value = JSONObject(request("POST", "/api/v1/servers/${server.id}/containers/actions",
            token = session.token, body = body, idempotencyKey = key)).getJSONObject("job")
        return HubContainers.parseJob(value.fields("id", "server_id", "state", "exit_code"), server.id)
            ?: throw IOException("Hub прислал неверное задание контейнера")
    }

    fun containerJob(session: HubSession, serverId: String, jobId: String,
                     action: HubContainerAction, id: String): HubContainerJob {
        require(INCIDENT_ID.matches(serverId) && INCIDENT_ID.matches(jobId) && HubContainers.validId(id)) {
            "Неверное задание контейнера"
        }
        if (!session.canAdminister(serverId)) throw HubIdentityException()
        val value = JSONObject(request("GET", "/api/v1/jobs/$jobId", token = session.token)).getJSONObject("job")
        val output = when (val raw = value.opt("output")) {
            null, JSONObject.NULL -> ""
            is String -> raw
            else -> throw IOException("Hub прислал неверный результат задания")
        }
        val result = try {
            if (output.toByteArray(StandardCharsets.UTF_8).size > 512 || output.isBlank()) null else
                HubContainers.parseResult(JSONObject(output).allFields(), action, id)
        } catch (_: JSONException) { null }
        return HubContainers.parseJob(value.fields("id", "server_id", "state", "exit_code"), serverId, result)
            ?.takeIf { it.id == jobId } ?: throw IOException("Hub прислал неверное задание контейнера")
    }

    fun logout(token: String) {
        request("DELETE", "/api/v1/session", token = token)
    }

    private fun request(method: String, path: String, token: String? = null, body: ByteArray? = null,
                        idempotencyKey: String? = null): String {
        val connection = (URI(origin + path).toURL().openConnection() as HttpsURLConnection)
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        connection.requestMethod = method
        connection.setRequestProperty("Accept", "application/json")
        if (token != null) connection.setRequestProperty("Authorization", "Bearer $token")
        if (idempotencyKey != null) connection.setRequestProperty("Idempotency-Key", idempotencyKey)
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setFixedLengthStreamingMode(body.size)
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            if (status !in 200..299) throw HubHttpException(status)
            if (status == 204) return ""
            return connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(8192)
                while (true) {
                    val count = input.read(chunk)
                    if (count < 0) break
                    if (output.size() + count > MAX_RESPONSE_BYTES) throw IOException("Ответ Hub слишком большой")
                    output.write(chunk, 0, count)
                }
                String(output.toByteArray(), StandardCharsets.UTF_8)
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun JSONObject.fields(vararg keys: String): Map<String, Any?> = buildMap {
        for (key in keys) if (has(key)) put(key, opt(key).takeUnless { it === JSONObject.NULL })
    }

    private fun JSONObject.allFields(): Map<String, Any?> = buildMap {
        for (key in keys()) put(key, opt(key).takeUnless { it === JSONObject.NULL })
    }

    private fun JSONObject.plainFields(): Map<String, Any?> = buildMap {
        for (key in keys()) put(key, plainValue(opt(key)))
    }

    private fun plainValue(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> value.plainFields()
        is JSONArray -> (0 until value.length()).map { plainValue(value.opt(it)) }
        else -> value
    }

    private fun JSONObject.sessionFields(): Map<String, Any?> = buildMap {
        for (key in listOf("token", "expires_at", "user")) {
            if (!has(key)) continue
            val value = this@sessionFields.get(key)
            put(key, if (key == "user" && value is JSONObject) buildMap {
                for (field in listOf("id", "username", "role", "enabled", "revision", "created_at", "updated_at")) {
                    if (value.has(field)) put(field, value.get(field).takeUnless { it === JSONObject.NULL })
                }
            } else value.takeUnless { it === JSONObject.NULL })
        }
    }

    private companion object {
        const val MAX_RESPONSE_BYTES = 1024 * 1024
        val INCIDENT_ID = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    }
}
