/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertThrows
import org.junit.Test

class HubApiIncidentTest {
    @Test fun acknowledgementRejectsPathOutsideIncidentIdBeforeNetworkRequest() {
        val api = HubApi("https://hub.example.com")
        val session = HubSessionParser.login(mapOf("token" to "unused-session"), "owner")
        for (id in listOf("../session", "abc/ack", "", "\n", "00000000-0000-0000-0000-000000000000?token=x")) {
            assertThrows(IllegalArgumentException::class.java) {
                api.acknowledge(session, id)
            }
        }
    }

    @Test fun viewerCannotAcknowledgeBeforeAnyNetworkRequest() {
        val api = HubApi("https://hub.example.com")
        val session = HubSession("unused-session", HubIdentity("viewer-id", "guest", HubRole.VIEWER, false), null)
        assertThrows(HubIdentityException::class.java) {
            api.acknowledge(session, "00000000-0000-0000-0000-000000000000")
        }
    }

    @Test fun checkSummaryRejectsServerPathOutsideCanonicalIdBeforeNetworkRequest() {
        val api = HubApi("https://hub.example.com")
        val session = HubSession("unused-session", HubIdentity("viewer-id", "guest", HubRole.VIEWER, false), null)
        for (id in listOf("../session", "abc/checks", "", "00000000-0000-0000-0000-000000000000?token=x")) {
            assertThrows(IllegalArgumentException::class.java) { api.checks(session, id) }
        }
    }
}
