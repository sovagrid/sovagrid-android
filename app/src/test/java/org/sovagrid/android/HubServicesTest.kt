/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class HubServicesTest {
    private val serverId = "11aa22bb-33cc-44dd-88ee-99ff00aa11bb"
    private val jobId = "aabbccdd-1122-3344-8899-aabbccddeeff"

    private fun server(enabled: Boolean = true): HubServer = HubMonitoring.parseServer(mapOf(
        "id" to serverId, "name" to "Gateway", "online" to true,
        "remote_commands_enabled" to enabled, "access_role" to "admin"
    ), null, null) ?: error("Expected server")

    private fun session(role: HubRole = HubRole.ADMIN, server: HubServer = server()): HubSession =
        HubSession("unused", HubIdentity("admin-id", "admin", role, false), null).also {
            it.updateAccess(HubAccess("all", 0, role == HubRole.ADMIN), listOf(server))
        }

    private val status = HubServiceControl("nginx.service", "ok", 1_783_000_000,
        "loaded", "active", "running")

    @Test fun exactUnitAndReservedAccessServicesAreStatusOnly() {
        for (name in listOf("nginx.service", "custom-daemon@one.service", "my_app.service"))
            assertTrue(name, HubServices.validUnit(name))
        for (name in listOf("../ssh.service", "ssh.socket", "evil.service;id", "x@.service", ""))
            assertFalse(name, HubServices.validUnit(name))
        for (name in listOf("ssh.service", "sshd@host.service", "docker.service", "wg-quick@wg0.service",
            "sovagrid-agent.service", "systemd-networkd.service", "reverse-tunnel.service", "AmneziaWG.service")) {
            assertTrue(name, HubServices.protectedUnit(name))
            assertFalse(HubServices.canMutate(server(), session(), name, status.copy(unit = name), 0))
        }
        assertFalse(HubServices.protectedUnit("nginx.service"))
    }

    @Test fun adminAndFreshMatchingProbeAreRequiredForMutation() {
        val host = server()
        assertTrue(HubServices.canCheck(host, session()))
        assertTrue(HubServices.canMutate(host, session(), "nginx.service", status, 84_999))
        assertFalse(HubServices.canMutate(host, session(), "nginx.service", status, 85_000))
        assertFalse(HubServices.canMutate(host, session(), "nginx.service", status, -1))
        assertFalse(HubServices.canMutate(host, session(), "other.service", status, 0))
        assertFalse(HubServices.canMutate(host, session(), "nginx.service", status.copy(sourceStatus = "unavailable"), 0))
        assertFalse(HubServices.canMutate(host, session(HubRole.OPERATOR), "nginx.service", status, 0))
        val disabled = server(false)
        assertFalse(HubServices.canCheck(disabled, session(server = disabled)))
        assertFalse(HubServices.canMutate(disabled, session(server = disabled), "nginx.service", status, 0))
    }

    @Test fun statusAndJobParsersRejectUnknownOrStaleLookingResults() {
        val fields = mapOf<String, Any?>(
            "source_status" to "ok", "unit" to "nginx.service", "observed_at" to 1_783_000_000L,
            "load_state" to "loaded", "active_state" to "active", "sub_state" to "running")
        assertEquals(status, HubServices.parseControl(fields, "nginx.service"))
        assertNull(HubServices.parseControl(fields + ("token" to "private"), "nginx.service"))
        assertNull(HubServices.parseControl(fields + ("active_state" to "active\nsecret"), "nginx.service"))
        assertNull(HubServices.parseControl(fields + ("unit" to "ssh.service"), "nginx.service"))
        assertNotNull(HubServices.parseControl(fields.mapValues { (key, value) ->
            when (key) {
                "source_status" -> "unavailable"
                "unit" -> value
                else -> null
            }
        }, "nginx.service"))

        val resultFields = mapOf<String, Any?>(
            "action" to "restart", "unit" to "nginx.service", "result" to "ok",
            "load_state" to "loaded", "active_state" to "active", "sub_state" to "running")
        val result = HubServices.parseResult(resultFields)
        assertEquals(HubServiceAction.RESTART, result?.action)
        assertNull(HubServices.parseResult(resultFields + ("PrivateKey" to "secret")))
        assertNull(HubServices.parseResult(resultFields + ("result" to "unknown")))
        val job = HubServices.parseJob(mapOf("id" to jobId, "server_id" to serverId,
            "state" to "succeeded", "exit_code" to 0), serverId, result)
        assertTrue(job?.terminal == true)
        assertEquals("ok", job?.result?.result)
        assertNull(HubServices.parseJob(mapOf("id" to jobId, "server_id" to "../server",
            "state" to "succeeded"), serverId))
        assertNull(HubServices.parseJob(mapOf("id" to jobId, "server_id" to serverId,
            "state" to "running"), serverId))
    }

    @Test fun apiBlocksProtectedMutationAndViewerBeforeNetwork() {
        val api = HubApi("https://hub.example.com")
        val host = server()
        val key = "dd30fd5b-a911-423c-944f-c583f3ba22a1"
        assertThrows(HubIdentityException::class.java) {
            api.queueServiceAction(session(), host, HubServiceAction.STOP, "ssh.service", key,
                status.copy(unit = "ssh.service"), 0)
        }
        assertThrows(HubIdentityException::class.java) {
            api.queueServiceAction(session(HubRole.VIEWER), host, HubServiceAction.STATUS,
                "nginx.service", key)
        }
        assertThrows(IllegalArgumentException::class.java) {
            api.serviceControl(session(), "../server", "nginx.service")
        }
    }
}
