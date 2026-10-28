/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import java.io.IOException
import java.security.MessageDigest
import java.security.PublicKey
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64

data class Endpoint(val host: String, val port: Int, val username: String) {
    init {
        require(host.isNotBlank() && host.none(Char::isWhitespace)) { "Invalid host" }
        require(port in 1..65535) { "Invalid port" }
        require(username.isNotBlank() && username.none(Char::isWhitespace)) { "Invalid username" }
    }
}

/** A complete SSH wire-format public key, not the JCE/X.509 encoding. */
data class HostKeySnapshot(val algorithm: String, val wireBase64: String) {
    val fingerprintSha256: String
        get() = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(Base64.getDecoder().decode(wireBase64))
        )

    companion object {
        fun from(key: PublicKey): HostKeySnapshot {
            val buffer = Buffer.PlainBuffer()
            buffer.putPublicKey(key)
            return HostKeySnapshot(KeyType.fromKey(key).toString(), Base64.getEncoder().encodeToString(buffer.compactData))
        }

        fun algorithmFromWire(wireBase64: String): String? = runCatching {
            val wire = ByteBuffer.wrap(Base64.getDecoder().decode(wireBase64))
            val length = wire.int
            if (length !in 1..128 || length > wire.remaining()) return@runCatching null
            val bytes = ByteArray(length)
            wire.get(bytes)
            String(bytes, StandardCharsets.US_ASCII)
        }.getOrNull()
    }
}

enum class PinDecision { NEW, TRUSTED, CHANGED }

object HostKeyPolicy {
    fun assess(pinnedWireBase64: String?, presentedWireBase64: String): PinDecision {
        if (pinnedWireBase64 == null) return PinDecision.NEW
        val saved = runCatching { Base64.getDecoder().decode(pinnedWireBase64) }.getOrNull()
            ?: return PinDecision.CHANGED
        val presented = runCatching { Base64.getDecoder().decode(presentedWireBase64) }.getOrNull()
            ?: return PinDecision.CHANGED
        return if (MessageDigest.isEqual(saved, presented)) PinDecision.TRUSTED else PinDecision.CHANGED
    }
}

class HostKeyChangedException(
    val expectedFingerprint: String,
    val presentedFingerprint: String,
    val endpoint: Endpoint? = null
) : IOException("SSH host key changed")

internal class ProbeVerifier : HostKeyVerifier {
    @Volatile var observed: HostKeySnapshot? = null
        private set

    override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
        observed = HostKeySnapshot.from(key)
        return false // The first connection must end before any authentication.
    }

    override fun findExistingAlgorithms(hostname: String, port: Int): List<String> = emptyList()
}

internal class PinnedVerifier(
    private val endpoint: Endpoint,
    private val pinnedWireBase64: String
) : HostKeyVerifier {
    @Volatile var rejected: HostKeySnapshot? = null
        private set

    override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
        val presented = HostKeySnapshot.from(key)
        val valid = hostname.equals(endpoint.host, ignoreCase = true) && port == endpoint.port &&
            HostKeyPolicy.assess(pinnedWireBase64, presented.wireBase64) == PinDecision.TRUSTED
        if (!valid) rejected = presented
        return valid
    }

    override fun findExistingAlgorithms(hostname: String, port: Int): List<String> {
        if (!hostname.equals(endpoint.host, ignoreCase = true) || port != endpoint.port) return emptyList()
        return HostKeySnapshot.algorithmFromWire(pinnedWireBase64)?.let(::listOf) ?: emptyList()
    }
}
