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

class HubFilesystemAlertsTest {
    private val serverId = "11aa22bb-33cc-44dd-88ee-99ff00aa11bb"
    private val rule = mapOf("mountpoint" to "/srv/data", "metric" to "space", "threshold_percent" to 85)
    private val mount = mapOf("mountpoint" to "/srv/data", "fstype" to "ext4",
        "space_used_percent" to 87.5, "inodes_used_percent" to 10.0)
    private val observation = mapOf("mountpoint" to "/srv/data", "metric" to "space",
        "status" to "alert", "used_percent" to 87.5)
    private val state = mapOf<String, Any?>(
        "server_id" to serverId, "revision" to 3L, "hold_seconds" to 120,
        "rules" to listOf(rule), "source_status" to "ok", "observed_at" to 1_783_000_000L,
        "filesystems" to listOf(mount), "observations" to listOf(observation))

    @Test fun freshFilesystemCanBeSelectedButPartialOrOfflineCannot() {
        val parsed = HubFilesystemAlerts.parse(state, serverId) ?: error("Expected valid state")
        val server = HubMonitoring.parseServer(mapOf("id" to serverId, "name" to "Ubuntu", "online" to true),
            null, null) ?: error("Expected server")
        assertEquals(listOf("/srv/data" to "space", "/srv/data" to "inodes"),
            HubFilesystemAlerts.available(parsed, server))
        assertTrue(HubFilesystemAlerts.available(parsed.copy(sourceStatus = "partial"), server).isEmpty())
        assertTrue(HubFilesystemAlerts.available(parsed, server.copy(online = false)).isEmpty())
        assertNull(HubFilesystemAlerts.parse(state + ("server_id" to "other"), serverId))
    }

    @Test fun parserRejectsContradictoryAndDuplicateAlertEvidence() {
        assertNotNull(HubFilesystemAlerts.parse(state, serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("observations" to listOf(observation + ("status" to "normal"))), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("observations" to listOf(observation + ("used_percent" to null))), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("rules" to listOf(rule, rule)), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("filesystems" to listOf(mount, mount)), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("source_status" to "partial"), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("rules" to listOf(rule + ("mountpoint" to "/srv/../data"))), serverId))
        assertNull(HubFilesystemAlerts.parse(state + ("rules" to listOf(rule + ("threshold_percent" to true))), serverId))
    }

    @Test fun nullMetricsAndUnknownObservationAreExplicitNotHealthy() {
        val unavailable = state + mapOf("filesystems" to listOf(mount + ("inodes_used_percent" to null)),
            "observations" to listOf(observation + mapOf("status" to "unknown", "used_percent" to null)))
        val parsed = HubFilesystemAlerts.parse(unavailable, serverId)
        assertNotNull(parsed)
        assertEquals("unknown", parsed!!.observations.single().status)
        assertNull(parsed.observations.single().usedPercent)
    }

    @Test fun proposalRequiresExactUniquePairsAndBoundedThresholds() {
        val valid = HubFilesystemRule("/srv/data", "space", 90)
        assertTrue(HubFilesystemAlerts.validProposal(listOf(valid), 0))
        assertFalse(HubFilesystemAlerts.validProposal(listOf(valid, valid), 0))
        assertFalse(HubFilesystemAlerts.validProposal(listOf(valid.copy(thresholdPercent = 101)), 0))
        assertFalse(HubFilesystemAlerts.validProposal(listOf(valid.copy(metric = "command")), 0))
        assertFalse(HubFilesystemAlerts.validProposal(listOf(valid.copy(mountpoint = "/srv/../data")), 0))
        assertFalse(HubFilesystemAlerts.validProposal(listOf(valid), 86401))
    }

    @Test fun viewerCannotSendMutationBeforeAnyNetworkRequest() {
        val parsed = HubFilesystemAlerts.parse(state, serverId) ?: error("Expected valid state")
        val server = HubMonitoring.parseServer(mapOf("id" to serverId, "name" to "Ubuntu", "online" to true,
            "access_role" to "viewer"), null, null) ?: error("Expected server")
        val session = HubSession("unused", HubIdentity("viewer-id", "viewer", HubRole.VIEWER, false), null).also {
            it.updateAccess(HubAccess("all", 0, false), listOf(server))
        }
        assertThrows(HubIdentityException::class.java) {
            HubApi("https://hub.example.com").saveFilesystemAlerts(session, parsed, parsed.rules, 60)
        }
    }
}
