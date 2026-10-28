/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import org.junit.Assert.*
import org.junit.Test
import java.security.GeneralSecurityException
import javax.crypto.KeyGenerator

class SshKeyEnvelopeTest {
    private val metadata = SshKeyMetadata("00000000-0000-0000-0000-000000000000", "Телефон", "ssh-ed25519 public comment", 100)
    private fun wrappingKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test fun encryptedSeedsRoundTripWithFreshNonceAndNoPlaintextInCiphertext() {
        val key = wrappingKey()
        val seed = ByteArray(32) { it.toByte() }
        val first = SshKeyEnvelope.encrypt(seed, key, metadata)
        val second = SshKeyEnvelope.encrypt(seed, key, metadata)
        assertEquals(12, first.nonce.size)
        assertEquals(48, first.ciphertext.size)
        assertFalse(first.nonce.contentEquals(second.nonce))
        assertArrayEquals(seed, SshKeyEnvelope.decrypt(first, key, metadata))
        assertFalse(first.ciphertext.take(32).toByteArray().contentEquals(seed))
    }

    @Test fun modifiedMetadataCiphertextAndWrongDeviceKeyAreRejected() {
        val key = wrappingKey()
        val sealed = SshKeyEnvelope.encrypt(ByteArray(32) { it.toByte() }, key, metadata)
        for (changed in listOf(metadata.copy(id = "another-id"), metadata.copy(label = "Other"),
            metadata.copy(publicKey = "another public key"), metadata.copy(createdAt = 101))) {
            assertThrows(GeneralSecurityException::class.java) { SshKeyEnvelope.decrypt(sealed, key, changed) }
        }
        val tampered = sealed.copy(ciphertext = sealed.ciphertext.clone().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertThrows(GeneralSecurityException::class.java) { SshKeyEnvelope.decrypt(tampered, key, metadata) }
        assertThrows(GeneralSecurityException::class.java) { SshKeyEnvelope.decrypt(sealed, wrappingKey(), metadata) }
    }

    @Test fun internalReferencesCannotTurnIntoPathsOrExternalUris() {
        val id = metadata.id
        assertEquals(id, SshKeyReference.id(SshKeyReference.uri(id)))
        for (value in listOf("sovagrid-key:../../key", "sovagrid-key://$id", "sovagrid-key:$id?extra=1",
            "sovagrid-key:$id#fragment", "file:$id", "content:$id", "sovagrid-key:%2e%2e")) {
            assertNull(SshKeyReference.id(value))
        }
    }
}
