/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RemotePathTest {
    @Test fun normalizesAbsolutePathsAndDoesNotEscapeRoot() {
        assertEquals("/", RemotePath.normalize("/"))
        assertEquals("/srv/log", RemotePath.normalize("//srv///tmp/../log/."))
        assertEquals("/a", RemotePath.normalize("/../../a"))
        assertEquals("/", RemotePath.parent("/a"))
        assertEquals("/a", RemotePath.parent("/a/b/"))
        assertEquals("/a/имя с пробелом.txt", RemotePath.child("/a/", "имя с пробелом.txt"))
    }

    @Test fun refusesAmbiguousOrControlNames() {
        for (name in listOf("", ".", "..", "a/b", "a\u0000b", "line\nbreak")) {
            assertThrows(IllegalArgumentException::class.java) { RemotePath.child("/safe", name) }
        }
        assertThrows(IllegalArgumentException::class.java) { RemotePath.normalize("relative") }
        assertThrows(IllegalArgumentException::class.java) { RemotePath.normalize("/bad\u001bname") }
    }
}
