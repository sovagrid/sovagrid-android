/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

class ProfileSaveContractTest {
    @Test fun acceptsExactProfileContract() {
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString("[Interface]".toByteArray())
        val request = ProfileSaveContract.decode(1, "alpha-1-phone_2.conf", encoded)!!
        assertEquals("alpha-1-phone_2.conf", request.filename)
        assertArrayEquals("[Interface]".toByteArray(), request.bytes)
        request.bytes.fill(0)
        for (name in listOf("amnezia-awg2-phone.conf", "amnezia-wireguard-phone.conf")) {
            val amnezia = ProfileSaveContract.decode(1, name, encoded)!!
            assertEquals(name, amnezia.filename)
            amnezia.bytes.fill(0)
        }
    }

    @Test fun rejectsWrongVersionAndFilename() {
        for (version in listOf(null, "1", 0, 2, 1.0))
            assertNull(ProfileSaveContract.decode(version, "alpha-phone.conf", "YQ"))
        for (name in listOf(null, "../alpha-phone.conf", "alpha-../phone.conf", "Alpha-phone.conf",
            "a-phone.conf", "alpha-.conf", "alpha-phone.txt", "alpha-phone.conf/evil",
            "alpha-" + "x".repeat(33) + ".conf"))
            assertNull(ProfileSaveContract.decode(1, name, "YQ"))
    }

    @Test fun rejectsPaddingNonCanonicalAndOversizedData() {
        for (data in listOf(null, "", "YQ==", "YR", "YQ+", "YQ/", "!"))
            assertNull(ProfileSaveContract.decode(1, "alpha-phone.conf", data))
        val max = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16_384))
        val accepted = ProfileSaveContract.decode(1, "alpha-phone.conf", max)!!
        assertEquals(16_384, accepted.bytes.size)
        accepted.bytes.fill(0)
        val tooLarge = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16_385))
        assertNull(ProfileSaveContract.decode(1, "alpha-phone.conf", tooLarge))
    }
}
