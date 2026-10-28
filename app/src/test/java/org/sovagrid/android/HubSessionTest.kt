/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.*
import org.junit.Test

class HubSessionTest {
    private val gatewayId = "11aa22bb-33cc-44dd-88ee-99ff00aa11bb"
    private val targetId = "22aa33bb-44cc-55dd-88ee-99ff00aa22bb"
    private fun user(role: String = "viewer"): Map<String, Any?> = mapOf(
        "id" to "user-id", "username" to "Иван", "role" to role, "enabled" to true,
        "revision" to 1, "created_at" to 100, "updated_at" to 110L
    )

    private fun payload(identity: Any?): Map<String, Any?> = mapOf(
        "token" to "test-session-token", "expires_at" to 2_000_000_000L, "user" to identity
    )

    @Test fun absentUserKeepsLegacySingletonCompatibleWithoutGuessingForPresentUser() {
        val session = HubSessionParser.login(mapOf("token" to "old-session"), "old-owner")
        assertTrue(session.identity.legacy)
        assertNull(session.identity.id)
        assertEquals("old-owner", session.identity.username)
        assertEquals(HubRole.ADMIN, session.identity.role)
        assertTrue(session.identity.role.canAcknowledge)
        for (identity in listOf(null, true, "admin", emptyMap<String, Any?>())) {
            assertThrows(HubIdentityException::class.java) { HubSessionParser.login(payload(identity), "owner") }
        }
    }

    @Test fun rolesHaveExplicitAcknowledgementPolicyAndKeepReturnedIdentity() {
        for ((role, allowed) in listOf("viewer" to false, "operator" to true, "admin" to true)) {
            val session = HubSessionParser.login(payload(user(role)), "different-typed-name")
            assertEquals("user-id", session.identity.id)
            assertEquals("Иван", session.identity.username)
            assertEquals(role, session.identity.role.wireName)
            assertEquals(allowed, session.identity.role.canAcknowledge)
            assertFalse(session.identity.legacy)
            assertEquals(2_000_000_000L, session.expiresAt)
            assertFalse(session.toString().contains("test-session-token"))
        }
    }

    @Test fun malformedIdentityNeverFallsBackToAdministratorOrCoercesJsonTypes() {
        val malformed = listOf(
            user() + ("id" to ""), user() + ("id" to "a".repeat(65)), user() + ("id" to 7),
            user() + ("username" to "a".repeat(81)), user() + ("username" to "\nroot"),
            user() + ("username" to " root "), user() + ("role" to "root"),
            user() + ("role" to 1), user() + ("enabled" to false), user() + ("enabled" to "true"),
            user() + ("enabled" to 1), user() + ("revision" to "1"), user() + ("revision" to 1.0),
            user() + ("revision" to -1), user() + ("revision" to 9_007_199_254_740_992L),
            user() + ("created_at" to true), user() + ("updated_at" to 253_402_300_800L)
        ) + user().keys.map { field -> user() - field }
        for (identity in malformed) {
            assertThrows("Accepted $identity", HubIdentityException::class.java) {
                HubSessionParser.login(payload(identity), "owner")
            }
        }
    }

    @Test fun freshIdentityMustKeepPrincipalAndRoleAndCannotBecomeLegacy() {
        val expected = HubSessionParser.login(payload(user("operator")), "owner").identity
        HubSessionParser.confirm(mapOf("user" to user("operator") + ("revision" to 2)), expected)
        for (response in listOf(emptyMap(), mapOf("user" to null),
            mapOf("user" to user("operator") + ("id" to "other-user")),
            mapOf("user" to user("operator") + ("username" to "other-owner")),
            mapOf("user" to user("viewer")), mapOf("user" to user("admin")),
            mapOf("user" to user("operator") + ("enabled" to false)))) {
            assertThrows(HubIdentityException::class.java) { HubSessionParser.confirm(response, expected) }
        }
    }

    @Test fun tokenAndExpiryNeverAcceptTypeCoercionOrHeaderControls() {
        for (token in listOf(null, 123, "", "a\nb", "a b", "x".repeat(4097))) {
            assertThrows(HubIdentityException::class.java) {
                HubSessionParser.login(payload(user()) + ("token" to token), "owner")
            }
        }
        for (expiry in listOf(null, "2000000000", 2_000_000_000.0, true, -1, 0, Long.MAX_VALUE)) {
            assertThrows(HubIdentityException::class.java) {
                HubSessionParser.login(payload(user()) + ("expires_at" to expiry), "owner")
            }
        }
    }

    @Test fun selectedAccessUsesEachServerRoleAndCapsItByGlobalRole() {
        val session = HubSessionParser.login(payload(user("operator")), "owner")
        val access = HubSessionParser.access(mapOf("access" to mapOf(
            "mode" to "selected", "revision" to 2, "unrestricted_admin" to false
        )), session.identity)
        val gateway = HubMonitoring.parseServer(mapOf("id" to gatewayId, "name" to "Gateway",
            "access_role" to "viewer"), null, null) ?: error("Gateway")
        val target = HubMonitoring.parseServer(mapOf("id" to targetId, "name" to "Target",
            "access_role" to "admin"), null, null) ?: error("Target")
        session.updateAccess(access, listOf(gateway, target))
        assertEquals(HubRole.VIEWER, session.effectiveRole(gatewayId))
        assertEquals(HubRole.OPERATOR, session.effectiveRole(targetId))
        assertFalse(session.canAcknowledge(gatewayId))
        assertTrue(session.canAcknowledge(targetId))
        assertFalse(session.canAcknowledge("00000000-0000-0000-0000-000000000000"))
        assertThrows(HubIdentityException::class.java) {
            session.updateAccess(access, listOf(HubMonitoring.parseServer(
                mapOf("id" to gatewayId, "name" to "Gateway"), null, null
            ) ?: error("Legacy server")))
        }
        assertThrows(HubIdentityException::class.java) {
            session.updateAccess(access, listOf(target, target))
        }
    }

    @Test fun accessSummaryFailsClosedOnUnexpectedTypesOrAuthority() {
        val identity = HubSessionParser.login(payload(user("admin")), "owner").identity
        for (access in listOf(
            mapOf("mode" to "selected", "revision" to 0, "unrestricted_admin" to true),
            mapOf("mode" to "all", "revision" to "0", "unrestricted_admin" to true),
            mapOf("mode" to "all", "revision" to 0, "unrestricted_admin" to false),
            mapOf("mode" to "other", "revision" to 0, "unrestricted_admin" to false)
        )) assertThrows(HubIdentityException::class.java) {
            HubSessionParser.access(mapOf("access" to access), identity)
        }
        assertEquals("all", HubSessionParser.legacyAccess(identity).mode)
    }
}
