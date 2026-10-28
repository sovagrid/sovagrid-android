/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.sovagrid.ssh.HostKeySnapshot
import java.io.IOException
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/** Creates device keys and exports only their public OpenSSH line. */
class SshKeysActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val vault by lazy { SshKeyVault(this) }
    @Volatile private var disposed = false
    private var busy = false
    private var pendingPublicKey: String? = null
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        showKeys()
    }

    private fun Int.dp() = (this * resources.displayMetrics.density).roundToInt()
    private fun text(value: String, size: Float = 15f) = TextView(this).apply {
        text = value; textSize = size; setPadding(0, 8.dp(), 0, 8.dp())
    }

    private fun button(title: String, action: () -> Unit) = Button(this).apply {
        text = title; isAllCaps = false; isEnabled = !busy
        setOnClickListener { if (!busy) action() }
    }

    private fun showKeys(message: String = "") {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(16.dp(), 16.dp(), 16.dp(), 16.dp())
        }
        root.addView(text("SSH-ключи", 26f))
        root.addView(text("Создайте пару Ed25519 на телефоне. Публичный ключ скопируйте или сохраните и добавьте на сервер в ~/.ssh/authorized_keys. Приватный ключ останется защищённым на этом устройстве."))
        status = text(message, 14f).also(root::addView)
        root.addView(button(if (busy) "Подождите…" else "Создать ключ Ed25519", ::createDialog))
        val keys = try { vault.all() } catch (_: Exception) {
            status.text = "Не удалось прочитать сохранённые ключи. Попробуйте снова."
            emptyList()
        }
        if (keys.isEmpty()) root.addView(text("Сохранённых ключей пока нет."))
        for (key in keys) {
            root.addView(text(key.label, 19f))
            root.addView(text(fingerprint(key.publicKey), 13f))
            root.addView(button("Показать публичный ключ") { openPublicKey(key) }.apply {
                contentDescription = "Показать публичный ключ: ${key.label}"
            })
            if (intent.getBooleanExtra(SELECT_KEY, false)) root.addView(button("Использовать этот ключ") {
                setResult(RESULT_OK, Intent().setData(Uri.parse(SshKeyReference.uri(key.id))))
                finish()
            })
            root.addView(button("Удалить ключ с устройства") { confirmDelete(key) })
        }
        root.addView(button("Назад") { finish() })
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun createDialog() {
        val name = EditText(this).apply { setText("Мой телефон"); isSingleLine = true }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Новый SSH-ключ")
            .setMessage("Название поможет выбрать ключ. Пара создаётся локально; сервер автоматически не изменяется.")
            .setView(name)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Создать", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val label = name.text.toString().trim()
                if (label.isBlank() || label.length > 80 || label.any { Character.isISOControl(it) || it == '\u2028' || it == '\u2029' }) {
                    name.error = "Введите название от 1 до 80 символов без переносов."; return@setOnClickListener
                }
                dialog.dismiss(); busy = true; showKeys("Создаём защищённый ключ…")
                worker.execute {
                    val created = runCatching { vault.create(label) }
                    postUi {
                        busy = false
                        showKeys(if (created.isSuccess) "Ключ создан. Добавьте его публичную часть на сервер." else "Не удалось создать ключ. Проверьте доступность хранилища устройства.")
                        created.getOrNull()?.let(::showPublicKey)
                    }
                }
            }
        }
        dialog.show()
    }

    private fun openPublicKey(key: SshKeyMetadata) {
        busy = true; showKeys("Проверяем сохранённый ключ…")
        worker.execute {
            val checked = runCatching { vault.publicKey(key.id) }
            postUi {
                busy = false; showKeys(if (checked.isFailure) "Ключ недоступен или повреждён. Его публичная часть не выдана." else "")
                checked.getOrNull()?.let(::showPublicKey)
            }
        }
    }

    private fun showPublicKey(key: SshKeyMetadata) {
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(20.dp(), 8.dp(), 20.dp(), 8.dp())
            addView(text("Добавьте эту строку в ~/.ssh/authorized_keys нужного пользователя сервера. Это публичная часть; приватная часть в буфер не копируется.", 14f))
            addView(text(key.publicKey, 13f).apply { setTextIsSelectable(true) })
            addView(button("Копировать публичный ключ") {
                (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("SovaGrid public SSH key", key.publicKey))
                Toast.makeText(this@SshKeysActivity, "Публичный ключ скопирован", Toast.LENGTH_SHORT).show()
            })
            addView(button("Сохранить публичный .pub") {
                pendingPublicKey = key.publicKey
                startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    // text/plain makes DocumentsUI append .txt to the .pub title.
                    type = "application/octet-stream"; addCategory(Intent.CATEGORY_OPENABLE)
                    putExtra(Intent.EXTRA_TITLE, "sovagrid-${key.id.take(8)}.pub")
                }, EXPORT_PUBLIC_KEY)
            })
        }
        AlertDialog.Builder(this).setTitle(key.label).setView(ScrollView(this).apply { addView(body) })
            .setPositiveButton("Готово", null).show()
    }

    private fun confirmDelete(key: SshKeyMetadata) {
        val usages = try { HostStore(this).keyUsages(key.id) } catch (_: Exception) {
            status.text = "Не удалось проверить, где выбран ключ. Удаление отменено."; return
        }
        val used = if (usages.isEmpty()) "" else "\n\nВы выбирали этот ключ для:\n${usages.joinToString("\n")}\nДля следующего входа потребуется другой ключ или пароль."
        AlertDialog.Builder(this).setTitle("Удалить SSH-ключ?")
            .setMessage("«${key.label}»: приватная часть будет удалена с этого устройства. На сервере публичный ключ останется; приложение не меняет authorized_keys.$used")
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Удалить") { _, _ ->
                busy = true; showKeys("Удаляем ключ…")
                worker.execute {
                    val removed = runCatching {
                        vault.delete(key.id)
                        check(HostStore(this).forgetKeySelections(key.id))
                    }
                    postUi { busy = false; showKeys(if (removed.isSuccess) "Ключ удалён с устройства." else "Удаление ключа не подтверждено.") }
                }
            }.show()
    }

    @Deprecated("Uses the platform document picker.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != EXPORT_PUBLIC_KEY) return
        val public = pendingPublicKey
        pendingPublicKey = null
        val uri = data?.data?.takeIf { it.scheme == "content" }
        if (resultCode != RESULT_OK || public == null || uri == null) return
        busy = true; showKeys("Сохраняем публичный ключ…")
        worker.execute {
            val saved = runCatching {
                (contentResolver.openOutputStream(uri, "w") ?: throw IOException("Document unavailable")).use {
                    it.write((public + "\n").toByteArray(Charsets.UTF_8))
                }
            }
            postUi { busy = false; showKeys(if (saved.isSuccess) "Публичный ключ сохранён." else "Сохранение публичного ключа не подтверждено.") }
        }
    }

    private fun fingerprint(public: String): String = runCatching {
        HostKeySnapshot("ssh-ed25519", public.split(" ")[1]).fingerprintSha256
    }.getOrDefault("Ed25519")

    private fun postUi(action: () -> Unit) = runOnUiThread { if (!disposed) action() }

    override fun onDestroy() {
        disposed = true; pendingPublicKey = null; worker.shutdown()
        super.onDestroy()
    }

    companion object {
        const val SELECT_KEY = "select_key"
        private const val EXPORT_PUBLIC_KEY = 1601
    }
}
