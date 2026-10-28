/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.IOException
import kotlin.math.roundToInt

/** Legal notices are bundled from the exact root source files at build time. */
class AboutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16.dp(), 16.dp(), 16.dp(), 16.dp())
        }
        root.addView(text("О программе", 26f))
        root.addView(text("SovaGrid — Copyright (C) 2026 Jigokuraku01", 18f))
        root.addView(text("Исходный код: $SOURCE_URL", 14f))
        root.addView(Button(this).apply {
            text = "Открыть исходный код"
            isAllCaps = false
            setOnClickListener { openSource() }
        })
        root.addView(text("SovaGrid распространяется по AGPL-3.0-only с дополнительным условием сохранения авторства в ATTRIBUTION.md. Программа предоставляется «как есть», без каких-либо гарантий.", 15f))
        listOf(
            "Лицензия AGPLv3" to "LICENSE",
            "Авторство и дополнительное условие" to "ATTRIBUTION.md",
            "Уведомление" to "NOTICE",
            "Лицензии сторонних библиотек" to "THIRD_PARTY_NOTICES.txt"
        ).forEach { (title, file) ->
            root.addView(Button(this).apply {
                text = title
                isAllCaps = false
                setOnClickListener { showNotice(title, file) }
            })
        }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun openSource() {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(SOURCE_URL)))
        } catch (_: ActivityNotFoundException) {
            AlertDialog.Builder(this)
                .setMessage("На устройстве нет приложения для открытия ссылки: $SOURCE_URL")
                .setPositiveButton("Закрыть", null)
                .show()
        }
    }

    private fun showNotice(title: String, file: String) {
        val contents = try {
            assets.open("legal/$file").use { stream ->
                val bytes = stream.readBytes()
                if (bytes.size > MAX_NOTICE_BYTES) throw IOException("Legal notice exceeds bundled limit")
                bytes.toString(Charsets.UTF_8)
            }
        } catch (_: IOException) {
            AlertDialog.Builder(this)
                .setMessage("Текст $file не найден в этой сборке.")
                .setPositiveButton("Закрыть", null)
                .show()
            return
        }
        val content = text(contents, 14f).apply {
            setPadding(16.dp(), 8.dp(), 16.dp(), 8.dp())
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(ScrollView(this).apply { addView(content) })
            .setPositiveButton("Закрыть", null)
            .show()
    }

    private fun text(value: String, size: Float) = TextView(this).apply {
        text = value
        textSize = size
        setPadding(0, 6.dp(), 0, 6.dp())
    }

    private fun Int.dp() = (this * resources.displayMetrics.density).roundToInt()

    private companion object {
        const val SOURCE_URL = "https://github.com/sovagrid/sovagrid-android"
        const val MAX_NOTICE_BYTES = 128 * 1024
    }
}
