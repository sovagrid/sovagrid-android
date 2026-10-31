/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.net.Uri
import android.os.Handler
import android.os.Looper

/** SSH secrets exist only in memory and are erased when the connection or handoff ends. */
internal sealed interface SessionSshCredential {
    fun duplicate(): SessionSshCredential
    fun clear()

    class Password(val chars: CharArray) : SessionSshCredential {
        override fun duplicate(): SessionSshCredential = Password(chars.copyOf())
        override fun clear() = chars.fill('\u0000')
    }

    class Key(val uri: Uri, val passphrase: CharArray) : SessionSshCredential {
        override fun duplicate(): SessionSshCredential = Key(uri, passphrase.copyOf())
        override fun clear() = passphrase.fill('\u0000')
    }
}

internal class SessionSshHandoff(
    val serverId: String,
    val target: SessionSshCredential,
    val gateway: SessionSshCredential?
) {
    fun clear() {
        target.clear()
        gateway?.clear()
    }
}

/** One-time activity handoff; the Intent contains only the saved server ID. */
internal object EphemeralSshHandoff {
    private val handler = Handler(Looper.getMainLooper())
    private var pending: SessionSshHandoff? = null
    private var expiresAtNanos = 0L

    @Synchronized fun offer(value: SessionSshHandoff) {
        pending?.clear()
        pending = value
        expiresAtNanos = System.nanoTime() + 30_000_000_000L
        handler.postDelayed({
            synchronized(this) {
                if (pending === value) {
                    pending = null
                    expiresAtNanos = 0L
                    value.clear()
                }
            }
        }, 30_000)
    }

    @Synchronized fun take(serverId: String): SessionSshHandoff? {
        val value = pending ?: return null
        pending = null
        val expired = System.nanoTime() - expiresAtNanos >= 0
        expiresAtNanos = 0L
        if (expired || value.serverId != serverId) {
            value.clear()
            return null
        }
        return value
    }

    @Synchronized fun clearPending() {
        pending?.clear()
        pending = null
        expiresAtNanos = 0L
    }
}
