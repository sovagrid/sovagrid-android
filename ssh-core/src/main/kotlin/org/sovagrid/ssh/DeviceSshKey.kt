/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil
import java.security.SecureRandom
import java.util.Base64

/** Standard Ed25519/OpenSSH formats, using the existing Bouncy Castle encoders. */
object DeviceSshKey {
    fun generateSeed(): ByteArray = Ed25519PrivateKeyParameters(SecureRandom()).encoded

    fun publicKey(seed: ByteArray, comment: String): String {
        require(seed.size == 32) { "Invalid Ed25519 seed" }
        require(comment.matches(Regex("[A-Za-z0-9_.@-]{1,80}"))) { "Invalid SSH comment" }
        val public = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey()
        return "ssh-ed25519 ${Base64.getEncoder().encodeToString(OpenSSHPublicKeyUtil.encodePublicKey(public))} $comment"
    }

    /** SSHJ accepts this text only in memory; production never writes it to a file. */
    fun privateKey(seed: ByteArray): String {
        require(seed.size == 32) { "Invalid Ed25519 seed" }
        val encoded = OpenSSHPrivateKeyUtil.encodePrivateKey(Ed25519PrivateKeyParameters(seed, 0))
        return try {
            val body = Base64.getMimeEncoder(70, byteArrayOf(10)).encodeToString(encoded)
            "-----BEGIN OPENSSH PRIVATE KEY-----\n$body\n-----END OPENSSH PRIVATE KEY-----\n"
        } finally { encoded.fill(0) }
    }
}
