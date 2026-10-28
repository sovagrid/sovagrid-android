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

class HubContainersTest {
    private val serverId = "11aa22bb-33cc-44dd-88ee-99ff00aa11bb"
    private val jobId = "aabbccdd-1122-3344-8899-aabbccddeeff"
    private val id = "a".repeat(64)
    private val container = HubContainer(id, "worker", "docker.io/library/nginx:stable", "running",
        "healthy", 0, 1.5, 2048)
    private val control = HubContainerControl("ok", id, 1_783_000_000, "running")

    private fun inventory(item: HubContainer = container, truncated: Boolean = false): HubContainerInventory =
        HubContainerInventory(1_783_000_000, HubContainerSource("docker", "ok", truncated, listOf(item)))

    private fun server(item: HubContainer = container, enabled: Boolean = true,
                       truncated: Boolean = false): HubServer = HubMonitoring.parseServer(mapOf(
        "id" to serverId, "name" to "Gateway", "online" to true,
        "remote_commands_enabled" to enabled, "access_role" to "admin"
    ), null, null)!!.copy(containers = inventory(item, truncated))

    private fun session(host: HubServer, role: HubRole = HubRole.ADMIN): HubSession =
        HubSession("unused", HubIdentity("admin-id", "admin", role, false), null).also {
            it.updateAccess(HubAccess("all", 0, role == HubRole.ADMIN), listOf(host))
        }

    private fun rawInventory(item: Map<String, Any?> = mapOf(
        "id" to id, "name" to "worker", "image" to "docker.io/library/nginx:stable",
        "state" to "running", "health" to "healthy", "restarts" to 0,
        "cpu_percent" to 1.5, "memory_bytes" to 2048L
    ), truncated: Boolean = false): Map<String, Any?> = mapOf(
        "version" to 1, "collected_at" to 1_783_000_000L,
        "engines" to listOf(
            mapOf("engine" to "docker", "source_status" to "ok", "reason" to null,
                "truncated" to truncated, "containers" to listOf(item)),
            mapOf("engine" to "podman", "source_status" to "unavailable", "reason" to "no_socket",
                "truncated" to false, "containers" to emptyList<Any>())
        )
    )

    @Test fun fullInventoryAndExactIdAreRequired() {
        val parsed = HubContainers.parseInventory(rawInventory())
        assertEquals(id, parsed?.docker?.containers?.single()?.id)
        assertTrue(parsed?.docker?.complete == true)
        assertFalse(HubContainers.validId(id.take(12)))
        assertFalse(HubContainers.validId(id.uppercase()))
        assertNull(HubContainers.parseInventory(rawInventory() + ("secret" to "unsafe")))
        assertNull(HubContainers.parseInventory(rawInventory(truncated = false).let { fields ->
            fields + ("engines" to (fields["engines"] as List<*>).reversed())
        }))
        val duplicate = rawInventory().let { fields ->
            val engines = fields["engines"] as List<*>
            val docker = engines[0] as Map<*, *>
            fields + ("engines" to listOf(docker + ("containers" to listOf(
                (docker["containers"] as List<*>)[0], (docker["containers"] as List<*>)[0]
            )), engines[1]))
        }
        assertNull(HubContainers.parseInventory(duplicate))
    }

    @Test fun protectedAndIncompleteSourcesRemainReadOnly() {
        for (name in listOf("sovagrid-hub-1", "ssh-gateway", "reverse-tunnel")) {
            val protected = container.copy(name = name)
            val host = server(protected)
            assertTrue(HubContainers.protected(protected))
            assertFalse(HubContainers.canCheck(host, session(host), protected))
            assertFalse(HubContainers.canMutate(host, session(host), protected,
                control.copy(id = protected.id), 0))
        }
        val host = server(truncated = true)
        assertFalse(HubContainers.canCheck(host, session(host), container))
        val disabled = server(enabled = false)
        assertFalse(HubContainers.canCheck(disabled, session(disabled), container))
        val allowed = server()
        assertFalse(HubContainers.canCheck(allowed, session(allowed, HubRole.OPERATOR), container))
        assertTrue(HubContainers.canCheck(allowed, session(allowed), container))
    }

    @Test fun mutationRequiresFreshMatchingStatusProof() {
        val host = server()
        val admin = session(host)
        assertTrue(HubContainers.canMutate(host, admin, container, control, 84_999))
        assertFalse(HubContainers.canMutate(host, admin, container, control, 85_000))
        assertFalse(HubContainers.canMutate(host, admin, container, control, -1))
        assertFalse(HubContainers.canMutate(host, admin, container, control.copy(id = "b".repeat(64)), 0))
        assertFalse(HubContainers.canMutate(host, admin, container, control.copy(sourceStatus = "unavailable"), 0))
    }

    @Test fun controlResultAndJobRejectMismatchedOrContradictoryReplies() {
        val controlFields = mapOf<String, Any?>("source_status" to "ok", "engine" to "docker",
            "id" to id, "observed_at" to 1_783_000_000L, "state" to "running")
        assertEquals(control, HubContainers.parseControl(controlFields, id))
        assertNull(HubContainers.parseControl(controlFields + ("id" to "b".repeat(64)), id))
        assertNull(HubContainers.parseControl(controlFields + ("private" to "secret"), id))
        assertNotNull(HubContainers.parseControl(controlFields + mapOf(
            "source_status" to "unavailable", "observed_at" to null, "state" to null), id))

        val result = mapOf<String, Any?>("action" to "stop", "id" to id, "result" to "ok", "state" to "exited")
        assertEquals("exited", HubContainers.parseResult(result, HubContainerAction.STOP, id)?.state)
        assertNull(HubContainers.parseResult(result + ("state" to "running"), HubContainerAction.STOP, id))
        assertNull(HubContainers.parseResult(result + ("action" to "restart"), HubContainerAction.STOP, id))
        assertNull(HubContainers.parseResult(result + ("secret" to "x"), HubContainerAction.STOP, id))
        val job = HubContainers.parseJob(mapOf("id" to jobId, "server_id" to serverId,
            "state" to "succeeded", "exit_code" to 0), serverId)
        assertTrue(job?.terminal == true)
        assertNull(HubContainers.parseJob(mapOf("id" to jobId, "server_id" to serverId,
            "state" to "running"), serverId))
    }

    @Test fun apiRejectsWrongRightsIdAndProofBeforeNetwork() {
        val api = HubApi("https://hub.example.com")
        val host = server()
        val key = "dd30fd5b-a911-423c-944f-c583f3ba22a1"
        assertThrows(HubIdentityException::class.java) {
            api.queueContainerAction(session(host, HubRole.VIEWER), host,
                HubContainerAction.STATUS, container, key)
        }
        assertThrows(HubIdentityException::class.java) {
            api.queueContainerAction(session(host), host,
                HubContainerAction.STOP, container, key, control, 85_000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            api.queueContainerAction(session(host), host,
                HubContainerAction.STATUS, container, "NOT-A-UUID")
        }
        assertThrows(IllegalArgumentException::class.java) {
            api.containerControl(session(host), serverId, id.take(12))
        }
    }
}
