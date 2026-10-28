/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.net.Uri
import java.io.IOException

internal object SshKeyPicker {
    fun choose(activity: Activity, requestCode: Int, onLaunch: () -> Unit = {}) {
        AlertDialog.Builder(activity)
            .setTitle("Выбрать SSH-ключ")
            .setItems(arrayOf("Мои ключи SovaGrid / создать новый", "Импортировать файл ключа")) { _, selected ->
                val intent = if (selected == 0) Intent(activity, SshKeysActivity::class.java)
                    .putExtra(SshKeysActivity.SELECT_KEY, true)
                else Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    type = "*/*"
                    addCategory(Intent.CATEGORY_OPENABLE)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                onLaunch()
                activity.startActivityForResult(intent, requestCode)
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    fun internal(uri: Uri?): Boolean = uri != null && SshKeyReference.id(uri.toString()) != null

    fun description(context: Context, uri: Uri?, gateway: Boolean = false): String {
        if (uri == null) return if (gateway) "Выбрать ключ промежуточного узла" else "Выбрать SSH-ключ"
        val id = SshKeyReference.id(uri.toString())
        return if (id != null) {
            val label = runCatching { SshKeyVault(context).all().firstOrNull { it.id == id }?.label }.getOrNull()
            "Ключ SovaGrid: ${label ?: "сохранённый"}"
        } else if (gateway) "Файл ключа промежуточного узла выбран" else "Файл ключа выбран"
    }

    /** This is the same SSHJ authentication path for generated and imported keys. */
    fun read(context: Context, uri: Uri): String {
        if (uri.scheme == "sovagrid-key") {
            val id = SshKeyReference.id(uri.toString()) ?: throw IOException("Invalid saved key reference")
            return SshKeyVault(context).privateKeyText(id)
        }
        if (uri.scheme != "content") throw IOException("Private key source is not supported")
        val bytes = ByteArray(128 * 1024 + 1)
        return try {
            (context.contentResolver.openInputStream(uri) ?: throw IOException("Private key unavailable")).use { stream ->
                var size = 0
                while (true) {
                    val count = stream.read(bytes, size, bytes.size - size)
                    if (count < 0) break
                    size += count
                    if (size == bytes.size) throw IOException("Private key too large")
                }
                String(bytes, 0, size, Charsets.UTF_8)
            }
        } finally { bytes.fill(0) }
    }
}
