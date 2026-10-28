/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import java.time.Instant
import java.time.ZoneId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HubMonitoringTest {
    private val serverId = "11aa22bb-33cc-44dd-88ee-99ff00aa11bb"
    private val checkId = "aabbccdd-1122-3344-8899-aabbccddeeff"
    private val incidentId = "00112233-4455-6677-8899-aabbccddeeff"
    private val epoch = Instant.parse("2026-10-26T20:00:00Z").epochSecond

    @Test fun typedContainerTlsAndFilesystemIncidentsDoNotBreakDashboard() {
        val base = mapOf<String, Any?>(
            "id" to incidentId, "server_id" to serverId, "server_name" to "Target",
            "state" to "firing", "opened_at" to epoch, "updated_at" to epoch,
            "resolved_at" to null, "acknowledged_at" to null,
            "current_value" to 91.0, "threshold" to 85.0, "subject" to "/srv/data")
        for (kind in listOf("filesystem:space:${"a".repeat(64)}", "filesystem:inodes:${"b".repeat(64)}",
            "container:${"c".repeat(64)}", "tls:$checkId", "high_root_inodes", "high_psi_io_some")) {
            val incident = HubMonitoring.parseIncident(base + ("kind" to kind))
            assertNotNull(kind, incident)
            assertFalse(HubMonitoring.incidentTitle(incident!!).isBlank())
        }
        assertNull(HubMonitoring.parseIncident(base + ("kind" to "filesystem:space:../../api")))
        assertNull(HubMonitoring.parseIncident(base + ("kind" to "container:${"z".repeat(64)}")))
    }

    @Test fun utcEpochIsKeptUntilFormattingAtTheDeviceBoundary() {
        val server = HubMonitoring.parseServer(
            mapOf("id" to serverId, "name" to "Gateway", "online" to true, "last_seen" to epoch),
            mapOf("collected_at" to epoch - 1, "cpu_percent" to 2.5),
            null
        ) ?: error("Expected valid server")
        assertEquals(epoch, server.lastSeen)
        assertEquals(epoch - 1, server.collectedAt)
        assertEquals("26.10.2026 20:00:00 UTC+00:00", HubMonitoring.localStamp(server.lastSeen, ZoneId.of("UTC")))
        assertEquals("26.10.2026 23:00:00 UTC+03:00", HubMonitoring.localStamp(server.lastSeen, ZoneId.of("Europe/Moscow")))
        assertNull(HubMonitoring.epoch("2026-10-26T20:00:00Z"))
        assertNull(HubMonitoring.epoch(true))
        assertEquals("—", HubMonitoring.localStamp(0, ZoneId.of("UTC")))
        assertNull(server.accessRole) // Earlier Hub versions omit this field.
        assertEquals(HubRole.OPERATOR, HubMonitoring.parseServer(
            mapOf("id" to serverId, "name" to "Gateway", "access_role" to "operator"), null, null
        )?.accessRole)
        assertNull(HubMonitoring.parseServer(mapOf(
            "id" to serverId, "name" to "Gateway", "access_role" to "root"
        ), null, null))
    }

    @Test fun rtcOffsetIsDiagnosticOnlyAndDoesNotAlterUtcEpoch() {
        val clock = HubMonitoring.parseClock(mapOf(
            "system_utc_epoch" to epoch,
            "timezone" to "Europe/Moscow",
            "ntp_synchronized" to false,
            "rtc_local_time" to false,
            "rtc_utc_epoch" to epoch + 165,
            "rtc_offset_seconds" to 165
        )) ?: error("Expected valid clock")
        assertEquals(epoch, clock.systemUtcEpoch)
        assertEquals(165L, clock.rtcOffsetSeconds)
        assertTrue(HubMonitoring.rtcOffset(clock).contains("+165 с"))
        assertTrue(HubMonitoring.rtcOffset(clock).contains("не отклонение от точного UTC"))
        assertNull(HubMonitoring.parseClock(mapOf(
            "system_utc_epoch" to epoch, "rtc_local_time" to false,
            "rtc_utc_epoch" to epoch + 165, "rtc_offset_seconds" to -165
        )))
    }

    @Test fun viewerCheckModelOmitsTargetsAndKeepsStaleStateSeparateFromLastFailure() {
        val check = HubMonitoring.parseCheck(mapOf(
            "id" to checkId, "name" to "Сайт", "kind" to "http", "enabled" to true,
            "interval_seconds" to 60, "timeout_seconds" to 5, "state" to "stale",
            "url" to "https://private.example/internal?secret=visible-only-to-admin",
            "host" to "private.example", "port" to 443
        ), mapOf(
            "observed_at" to epoch, "received_at" to epoch + 1,
            "status" to "down", "latency_ms" to 155,
            "http_status" to 502, "tls_expires_at" to epoch + 86400,
            "error_code" to "http_error", "response_body" to "private-response"
        )) ?: error("Expected valid check")
        assertEquals("stale", check.state)
        assertEquals("down", check.latest?.status)
        assertEquals("Нет свежих данных", HubMonitoring.checkState(check.state))
        assertEquals("Ответ HTTP вне диапазона 2xx", HubMonitoring.checkError(check.latest?.errorCode))
        assertFalse(check.toString().contains("private.example"))
        assertFalse(check.toString().contains("private-response"))
        assertNotNull(HubMonitoring.parseChecksSummary(
            mapOf("server_id" to serverId, "revision" to 2, "worker_seen_at" to epoch), serverId, listOf(check)
        ))
        assertNull(HubMonitoring.parseChecksSummary(
            mapOf("server_id" to checkId, "revision" to 2), serverId, listOf(check)
        ))
    }

    @Test fun checkIncidentShowsRecoveryAndOnlyValidatedSubject() {
        val fields = mapOf<String, Any?>(
            "id" to incidentId, "server_id" to serverId, "server_name" to "Gateway", "kind" to "check:$checkId",
            "state" to "resolved", "opened_at" to epoch, "updated_at" to epoch + 90,
            "resolved_at" to epoch + 90, "acknowledged_at" to null,
            "current_value" to 0.0, "threshold" to 1.0, "subject" to "Сайт"
        )
        val incident = HubMonitoring.parseIncident(fields) ?: error("Expected valid incident")
        assertEquals(serverId, incident.serverId)
        assertEquals("resolved", incident.state)
        assertEquals(epoch + 90, incident.resolvedAt)
        assertEquals("Проверка восстановлена: «Сайт»", HubMonitoring.incidentTitle(incident))
        val sanitized = HubMonitoring.parseIncident(fields + ("subject" to "секрет\nдругая строка"))
            ?: error("Expected incident with sanitized subject")
        assertNull(sanitized.subject)
        assertEquals("Сетевая проверка восстановлена", HubMonitoring.incidentTitle(sanitized))
        val firing = HubMonitoring.parseIncident(fields + ("state" to "firing")) ?: error("Expected firing incident")
        assertEquals("Недоступна проверка «Сайт»", HubMonitoring.incidentTitle(firing))
        assertNull(HubMonitoring.parseIncident(fields + ("opened_at" to "2026-10-26")))
        assertNull(HubMonitoring.parseIncident(fields + ("kind" to "check:../../session")))
        assertNull(HubMonitoring.parseIncident(fields + ("server_id" to "../../session")))
    }

    @Test fun malformedSuccessDoesNotBecomeHealthyCheck() {
        val definition = mapOf<String, Any?>(
            "id" to checkId, "name" to "Порт", "kind" to "tcp", "enabled" to true,
            "interval_seconds" to 60, "timeout_seconds" to 5, "state" to "up"
        )
        val result = mapOf<String, Any?>(
            "observed_at" to epoch, "received_at" to epoch + 1,
            "status" to "up", "latency_ms" to 10,
            "http_status" to null, "tls_expires_at" to null, "error_code" to null
        )
        assertNotNull(HubMonitoring.parseCheck(definition, result))
        assertNull(HubMonitoring.parseCheck(definition, result + ("http_status" to 200)))
        assertNull(HubMonitoring.parseCheck(definition, result + ("error_code" to "secret_message")))
        assertNull(HubMonitoring.parseCheck(definition + ("kind" to "http"), result))
    }

    @Test fun dnsSummaryAndRecoveryHistoryDoNotExposeTargetOrAnswers() {
        val definition = mapOf<String, Any?>(
            "id" to checkId, "name" to "Проверка DNS", "kind" to "dns", "enabled" to true,
            "interval_seconds" to 60, "timeout_seconds" to 5, "state" to "down",
            "host" to "private.example", "record_type" to "AAAA",
            "expected_ip" to "2001:db8::1"
        )
        val result = mapOf<String, Any?>(
            "observed_at" to epoch, "received_at" to epoch + 1,
            "status" to "down", "latency_ms" to 12,
            "http_status" to null, "tls_expires_at" to null,
            "error_code" to "dns_mismatch", "answer_ips" to listOf("2001:db8::2")
        )
        val check = HubMonitoring.parseCheck(definition, result) ?: error("Expected DNS check")
        assertEquals("DNS", HubMonitoring.checkKind(check.kind))
        assertEquals("Ответ DNS не соответствует ожидаемому", HubMonitoring.checkError(check.latest?.errorCode))
        assertFalse(check.toString().contains("private.example"))
        assertFalse(check.toString().contains("2001:db8"))
        assertNotNull(HubMonitoring.parseChecksSummary(
            mapOf("server_id" to serverId, "revision" to 3, "worker_seen_at" to epoch), serverId, listOf(check)
        ))
        val incident = HubMonitoring.parseIncident(mapOf(
            "id" to incidentId, "server_id" to serverId, "server_name" to "Gateway", "kind" to "check:$checkId",
            "state" to "resolved", "opened_at" to epoch, "updated_at" to epoch + 30,
            "resolved_at" to epoch + 30, "subject" to "Проверка DNS",
            "host" to "private.example", "answer_ips" to listOf("2001:db8::2")
        )) ?: error("Expected DNS recovery")
        assertEquals("Проверка восстановлена: «Проверка DNS»", HubMonitoring.incidentTitle(incident))
        assertFalse(incident.toString().contains("private.example"))
        assertFalse(incident.toString().contains("2001:db8"))
        assertNull(HubMonitoring.parseCheck(definition, result + ("http_status" to 200)))
        assertNull(HubMonitoring.parseCheck(definition, result + ("tls_expires_at" to epoch + 60)))
        assertNull(HubMonitoring.parseCheck(definition, result + ("error_code" to "connect_error")))
        assertNull(HubMonitoring.parseCheck(definition + ("kind" to "http"), result))
    }
}
