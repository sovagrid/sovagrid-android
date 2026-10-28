/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import org.sovagrid.ssh.Authentication
import org.sovagrid.ssh.AuthenticationFailedException
import org.sovagrid.ssh.HostKeyChangedException
import org.sovagrid.ssh.JumpHost
import org.sovagrid.ssh.RemoteEntry
import org.sovagrid.ssh.RemotePath
import org.sovagrid.ssh.SftpConnection
import org.sovagrid.ssh.SshClientCore
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Native SFTP browser for a saved SSH profile; local files always use Android's document picker. */
class FilesActivity : Activity() {
    private val hosts by lazy { HostStore(this) }
    private val ssh = SshClientCore()
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var server: SavedServer
    private var connection: SftpConnection? = null
    private var selectedKey: Uri? = null
    private var selectedGatewayKey: Uri? = null
    private var pendingDownload: String? = null
    private var pickerActive = false
    private val pickerHandler = Handler(Looper.getMainLooper())
    private var pickerTimeout: Runnable? = null
    private var busy = false
    private var generation = 0
    private val cancelled = AtomicBoolean(false)
    @Volatile private var disposed = false
    private var directory = "/"
    private lateinit var status: TextView
    private lateinit var loginButton: Button
    private var verifyButton: Button? = null
    private lateinit var passwordRadio: RadioButton
    private lateinit var keyRadio: RadioButton
    private lateinit var passwordField: EditText
    private lateinit var passphraseField: EditText
    private lateinit var keyButton: Button
    private var gatewayPasswordRadio: RadioButton? = null
    private var gatewayKeyRadio: RadioButton? = null
    private var gatewayPasswordField: EditText? = null
    private var gatewayPassphraseField: EditText? = null
    private var gatewayKeyButton: Button? = null
    private var pathLabel: TextView? = null
    private var pathField: EditText? = null
    private var items: LinearLayout? = null
    private var uploadButton: Button? = null
    private var refreshButton: Button? = null
    private var upButton: Button? = null
    private var cancelButton: Button? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val id = intent.getStringExtra("server_id")
        val saved = runCatching { hosts.all().firstOrNull { it.id == id } }.getOrNull()
        if (saved == null) { finish(); return }
        server = saved
        showLogin()
    }

    private fun column() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val padding = (14 * resources.displayMetrics.density).toInt()
        setPadding(padding, padding, padding, padding)
    }

    private fun text(value: String, size: Float = 16f) = TextView(this).apply {
        this.text = value
        textSize = size
        setPadding(0, 8, 0, 8)
    }

    private fun secret(hint: String) = EditText(this).apply {
        this.hint = hint
        isSingleLine = true
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun showLogin(message: String? = null) {
        verifyButton = null
        gatewayPasswordRadio = null
        gatewayKeyRadio = null
        gatewayPasswordField = null
        gatewayPassphraseField = null
        gatewayKeyButton = null
        val root = column()
        root.addView(Button(this).apply { text = "← Серверы"; setOnClickListener { finish() } })
        root.addView(text("Файлы · ${server.label}", 23f))
        root.addView(text("${server.endpoint.username}@${server.endpoint.host}:${server.endpoint.port}" +
            (server.jumpEndpoint?.let { " через ${it.username}@${it.host}:${it.port}" } ?: "")))
        status = text(message ?: "SSH-пароли и ключи используются только для текущего подключения.")
        root.addView(status)
        val targetPin = hosts.pin(server.id)
        val gatewayPin = if (server.jumpEndpoint == null) null else hosts.pin(server.id, gateway = true)
        if (server.jumpEndpoint != null && gatewayPin == null) {
            status.text = "Сначала сравните ключ промежуточного хоста с независимым источником. До этого SSH-данные не отправляются."
            verifyButton = Button(this).apply {
                text = "Получить ключ промежуточного хоста"
                setOnClickListener { probeHost(gateway = true) }
            }.also(root::addView)
            setContentView(ScrollView(this).apply { addView(root) })
            return
        }
        if (targetPin == null) {
            if (server.jumpEndpoint != null) {
                status.text = "Ключ промежуточного узла уже подтверждён. Введите данные промежуточного узла, чтобы получить ключ конечного сервера. Данные конечного сервера до подтверждения его ключа не отправляются."
                addGatewayCredentials(root)
            } else {
                status.text = "Сравните ключ сервера с независимым источником. До подтверждения SSH-данные не отправляются."
            }
            verifyButton = Button(this).apply {
                text = "Получить ключ конечного сервера"
                setOnClickListener { probeHost(gateway = false) }
            }.also(root::addView)
            setContentView(ScrollView(this).apply { addView(root) })
            return
        }
        if (server.jumpEndpoint != null) addGatewayCredentials(root)
        root.addView(text("Вход на конечный сервер", 18f))
        val choices = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        passwordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль" }
        keyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Ключ" }
        choices.addView(passwordRadio)
        choices.addView(keyRadio)
        choices.check(passwordRadio.id)
        root.addView(choices)
        passwordField = secret("SSH-пароль").also(root::addView)
        keyButton = Button(this).apply {
            text = "Выбрать SSH-ключ"
            setOnClickListener { chooseKey(REQUEST_KEY) }
        }.also(root::addView)
        passphraseField = secret("Пароль ключа (если есть)").also(root::addView)
        choices.setOnCheckedChangeListener { _, _ -> updateAuthFields() }
        updateAuthFields()
        loginButton = Button(this).apply { text = "Открыть файлы"; setOnClickListener { connect() } }
        root.addView(loginButton)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun addGatewayCredentials(root: LinearLayout) {
        root.addView(text("Вход на промежуточный хост", 18f))
        val choices = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        gatewayPasswordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль промежуточного узла" }
        gatewayKeyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Ключ промежуточного узла" }
        choices.addView(gatewayPasswordRadio)
        choices.addView(gatewayKeyRadio)
        choices.check(if (selectedGatewayKey == null) gatewayPasswordRadio!!.id else gatewayKeyRadio!!.id)
        root.addView(choices)
        gatewayPasswordField = secret("SSH-пароль промежуточного узла").also(root::addView)
        gatewayKeyButton = Button(this).apply {
            text = if (selectedGatewayKey == null) "Выбрать ключ промежуточного узла" else "Ключ промежуточного узла выбран для этого подключения"
            setOnClickListener { chooseKey(REQUEST_GATEWAY_KEY) }
        }.also(root::addView)
        gatewayPassphraseField = secret("Пароль ключа промежуточного узла (если есть)").also(root::addView)
        choices.setOnCheckedChangeListener { _, _ -> updateGatewayAuthFields() }
        updateGatewayAuthFields()
    }

    private fun updateAuthFields() {
        val targetKey = keyRadio.isChecked
        if (targetKey) passwordField.text?.clear() else passphraseField.text?.clear()
        passwordField.visibility = if (targetKey) View.GONE else View.VISIBLE
        keyButton.visibility = if (targetKey) View.VISIBLE else View.GONE
        passphraseField.visibility = if (targetKey && !SshKeyPicker.internal(selectedKey)) View.VISIBLE else View.GONE
    }

    private fun updateGatewayAuthFields() {
        val gatewayKey = gatewayKeyRadio?.isChecked == true
        if (gatewayKey) gatewayPasswordField?.text?.clear() else gatewayPassphraseField?.text?.clear()
        gatewayPasswordField?.visibility = if (gatewayKey) View.GONE else View.VISIBLE
        gatewayKeyButton?.visibility = if (gatewayKey) View.VISIBLE else View.GONE
        gatewayPassphraseField?.visibility = if (gatewayKey && !SshKeyPicker.internal(selectedGatewayKey)) View.VISIBLE else View.GONE
    }

    /** Probe rejects the target host key before target authentication; only a trusted gateway is authenticated. */
    private fun probeHost(gateway: Boolean) {
        if (busy || connection != null) return
        val endpoint = if (gateway) server.jumpEndpoint ?: return else server.endpoint
        val gatewayPin = if (!gateway && server.jumpEndpoint != null)
            hosts.pin(server.id, gateway = true) ?: return else null
        val gatewayCredentials = if (gatewayPin != null) credentials(true) ?: return else null
        val requestId = ++generation
        busy = true
        verifyButton?.isEnabled = false
        status.text = if (gatewayPin != null) "Проверяем сохранённый ключ промежуточного узла и получаем ключ конечного сервера…"
        else "Получаем ключ без передачи учётных данных…"
        worker.execute {
            try {
                val jump = if (gatewayCredentials != null)
                    JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(gatewayCredentials)) else null
                val snapshot = ssh.probe(endpoint, jump)
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    busy = false
                    verifyButton?.isEnabled = true
                    status.text = "Получен ${snapshot.fingerprintSha256}. Сравните его до подтверждения."
                    val credentialNotice = if (gatewayPin == null)
                        "До подтверждения этому SSH-хосту не переданы учётные данные."
                    else "Данные промежуточного узла отправлены только после проверки сохранённого ключа промежуточного узла; данные конечного сервера не отправлены."
                    AlertDialog.Builder(this)
                        .setTitle(if (gateway) "Подтвердите ключ промежуточного хоста" else "Подтвердите ключ конечного сервера")
                        .setMessage("${endpoint.host}:${endpoint.port}\n" +
                            "Тип: ${snapshot.algorithm}\n${snapshot.fingerprintSha256}\n\n" +
                            "Сравните fingerprint с сервером через независимый канал. " + credentialNotice)
                        .setPositiveButton("Совпадает, доверять") { _, _ ->
                            if (disposed || generation != requestId) return@setPositiveButton
                            if (hosts.setPin(server.id, snapshot.wireBase64, gateway)) {
                                showLogin("Ключ подтверждён. Следующий SSH-вход повторно проверит его.")
                            } else status.text = "Не удалось сохранить ключ; вход заблокирован."
                        }
                        .setNegativeButton("Отмена", null)
                        .show()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    busy = false
                    verifyButton?.isEnabled = true
                    status.text = when (error) {
                        is HostKeyChangedException -> "Ключ промежуточного хоста изменился. Вход заблокирован."
                        is AuthenticationFailedException -> "Неверные SSH-данные промежуточного хоста."
                        else -> "Не удалось получить ключ (${error.javaClass.simpleName}). Проверьте сеть и SSH-маршрут."
                    }
                }
            } finally {
                gatewayCredentials?.clear()
            }
        }
    }

    private sealed interface Credentials {
        fun clear()
        class Password(val value: CharArray) : Credentials { override fun clear() = value.fill('\u0000') }
        class Key(val uri: Uri, val passphrase: CharArray) : Credentials { override fun clear() = passphrase.fill('\u0000') }
    }

    private fun takeSecret(field: EditText): CharArray {
        val value = field.text
        val chars = CharArray(value.length) { value[it] }
        value.clear()
        return chars
    }

    private fun credentials(gateway: Boolean): Credentials? {
        val useKey = if (gateway) gatewayKeyRadio?.isChecked == true else keyRadio.isChecked
        if (useKey) {
            val uri = if (gateway) selectedGatewayKey else selectedKey
            if (uri == null) {
                status.text = if (gateway) "Выберите ключ промежуточного узла." else "Выберите ключ сервера."
                return null
            }
            return Credentials.Key(uri, takeSecret(if (gateway) gatewayPassphraseField!! else passphraseField))
        }
        return Credentials.Password(takeSecret(if (gateway) gatewayPasswordField!! else passwordField))
    }

    private fun authentication(request: Credentials): Authentication = when (request) {
        is Credentials.Password -> Authentication.Password(request.value)
        is Credentials.Key -> Authentication.PrivateKey(readKey(request.uri), request.passphrase)
    }

    private fun readKey(uri: Uri): String = SshKeyPicker.read(this, uri)

    private fun connect() {
        if (busy || connection != null) return
        val targetPin = hosts.pin(server.id) ?: return
        val gatewayPin = if (server.jumpEndpoint != null) hosts.pin(server.id, gateway = true) ?: return else null
        val target = credentials(false) ?: return
        val gateway = if (server.jumpEndpoint != null) credentials(true) ?: run { target.clear(); return } else null
        busy = true
        cancelled.set(false)
        val requestId = ++generation
        loginButton.isEnabled = false
        status.text = "Подключаемся и проверяем сохранённые ключи…"
        worker.execute {
            var opened: SftpConnection? = null
            try {
                val route = if (gateway != null) JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(gateway)) else null
                val active = ssh.openFiles(server.endpoint, targetPin, authentication(target), route)
                opened = active
                if (cancelled.get()) { active.close(); return@execute }
                val home = active.home()
                runOnUiThread {
                    if (disposed || generation != requestId) { closeAsync(active); return@runOnUiThread }
                    connection = active
                    directory = home
                    busy = false
                    showBrowser()
                    loadDirectory(home)
                }
            } catch (error: Exception) {
                opened?.let(::closeAsync)
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    busy = false
                    loginButton.isEnabled = true
                    status.text = when (error) {
                        is HostKeyChangedException -> "Ключ SSH-хоста изменился. Вход заблокирован; проверьте хост независимо."
                        is AuthenticationFailedException -> "Неверные данные входа: ${error.endpoint?.host ?: "сервер"}."
                        else -> "Не удалось открыть SFTP (${error.javaClass.simpleName})."
                    }
                }
            } finally {
                target.clear()
                gateway?.clear()
            }
        }
    }

    private fun showBrowser() {
        val root = column()
        root.addView(Button(this).apply { text = "← Серверы"; setOnClickListener { finish() } })
        root.addView(text("Файлы · ${server.label}", 23f))
        pathLabel = text(directory, 16f).also(root::addView)
        status = text("Подключено по SFTP. Выберите каталог или файл.").also(root::addView)
        val pathRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        pathField = EditText(this).apply {
            hint = "Путь на сервере, например /var/log"
            isSingleLine = true
            setText(directory)
        }.also { pathRow.addView(it, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)) }
        pathRow.addView(Button(this).apply {
            text = "Перейти"
            setOnClickListener {
                val path = runCatching { RemotePath.normalize(pathField?.text.toString()) }.getOrNull()
                if (path == null) status.text = "Введите абсолютный путь без управляющих символов."
                else loadDirectory(path)
            }
        })
        root.addView(pathRow)
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        upButton = Button(this).apply {
            text = "↑"
            contentDescription = "Родительский каталог"
            setOnClickListener { loadDirectory(RemotePath.parent(directory)) }
        }.also(actions::addView)
        refreshButton = Button(this).apply { text = "Обновить"; setOnClickListener { loadDirectory(directory) } }.also(actions::addView)
        uploadButton = Button(this).apply { text = "Загрузить файл"; setOnClickListener { chooseUpload() } }.also(actions::addView)
        root.addView(actions)
        cancelButton = Button(this).apply {
            text = "Отменить операцию"
            visibility = View.GONE
            setOnClickListener { cancelOperation() }
        }.also(root::addView)
        root.addView(Button(this).apply { text = "Отключиться"; setOnClickListener { disconnect("Отключено.") } })
        items = column().also(root::addView)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun setBusy(value: Boolean) {
        busy = value
        upButton?.isEnabled = !value
        refreshButton?.isEnabled = !value
        uploadButton?.isEnabled = !value
        pathField?.isEnabled = !value
        cancelButton?.visibility = if (value) View.VISIBLE else View.GONE
    }

    private fun loadDirectory(path: String) {
        if (busy) return
        val opened = connection ?: return
        val next = RemotePath.normalize(path)
        val requestId = generation
        setBusy(true)
        status.text = "Читаем $next…"
        worker.execute {
            try {
                val listing = opened.list(next)
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    directory = next
                    pathLabel?.text = next
                    pathField?.setText(next)
                    renderEntries(listing)
                    status.text = "${listing.size} объектов. Нажмите на файл, чтобы скачать."
                    setBusy(false)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    if (!opened.isOpen) disconnect("Соединение потеряно. Подключитесь снова.")
                    else { status.text = "Не удалось прочитать каталог (${error.javaClass.simpleName})."; setBusy(false) }
                }
            }
        }
    }

    private fun renderEntries(listing: List<RemoteEntry>) {
        val container = items ?: return
        container.removeAllViews()
        if (listing.isEmpty()) container.addView(text("Каталог пуст."))
        listing.forEach { entry ->
            container.addView(Button(this).apply {
                text = when {
                    entry.isDirectory -> "📁 ${entry.name}"
                    entry.isFile -> "📄 ${entry.name} · ${formatSize(entry.size)}"
                    else -> "↗ ${entry.name} · ссылка/спецфайл"
                }
                isAllCaps = false
                isEnabled = entry.isDirectory || entry.isFile
                setOnClickListener {
                    val full = RemotePath.child(directory, entry.name)
                    if (entry.isDirectory) loadDirectory(full)
                    else AlertDialog.Builder(this@FilesActivity)
                        .setTitle("Скачать ${entry.name}?")
                        .setMessage("Размер: ${formatSize(entry.size)}. Место сохранения выберите в системном окне Android.")
                        .setPositiveButton("Выбрать место") { _, _ -> chooseDownload(full, entry.name) }
                        .setNegativeButton("Отмена", null)
                        .show()
                }
            })
        }
    }

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024 -> "$bytes Б"
        bytes < 1024 * 1024 -> "${bytes / 1024} КБ"
        else -> "${bytes / (1024 * 1024)} МБ"
    }

    private fun chooseDownload(path: String, name: String) {
        pendingDownload = path
        pickerActive = true
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            type = "application/octet-stream"
            addCategory(Intent.CATEGORY_OPENABLE)
            putExtra(Intent.EXTRA_TITLE, name)
        }, REQUEST_DOWNLOAD)
    }

    private fun chooseUpload() {
        pickerActive = true
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }, REQUEST_UPLOAD)
    }

    private fun chooseKey(request: Int) {
        SshKeyPicker.choose(this, request) { pickerActive = true }
    }

    @Deprecated("Uses Android's system document picker on API 26+.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        pickerTimeout?.let(pickerHandler::removeCallbacks)
        pickerTimeout = null
        pickerActive = false
        val keySelection = requestCode == REQUEST_KEY || requestCode == REQUEST_GATEWAY_KEY
        val uri = data?.data?.takeIf { it.scheme == "content" || keySelection && SshKeyPicker.internal(it) }
        if ((requestCode == REQUEST_DOWNLOAD || requestCode == REQUEST_UPLOAD) && connection == null) {
            if (requestCode == REQUEST_DOWNLOAD && uri != null) {
                worker.execute { runCatching { DocumentsContract.deleteDocument(contentResolver, uri) } }
            }
            pendingDownload = null
            showLogin("SSH-соединение завершилось во время выбора файла. Подключитесь снова.")
            return
        }
        when (requestCode) {
            REQUEST_KEY -> if (resultCode == RESULT_OK) {
                if (!hosts.recordKeySelection(server.id, uri?.let { SshKeyReference.id(it.toString()) })) {
                    status.text = "Не удалось сохранить выбор ключа."; return
                }
                selectedKey = uri; passphraseField.text.clear()
                keyButton.text = SshKeyPicker.description(this, uri)
                updateAuthFields()
            }
            REQUEST_GATEWAY_KEY -> if (resultCode == RESULT_OK) {
                if (!hosts.recordKeySelection(server.id, uri?.let { SshKeyReference.id(it.toString()) }, gateway = true)) {
                    status.text = "Не удалось сохранить выбор ключа промежуточного узла."; return
                }
                selectedGatewayKey = uri; gatewayPassphraseField?.text?.clear()
                gatewayKeyButton?.text = SshKeyPicker.description(this, uri, gateway = true)
                updateGatewayAuthFields()
            }
            REQUEST_DOWNLOAD -> {
                val path = pendingDownload
                pendingDownload = null
                if (resultCode == RESULT_OK && uri != null && path != null) download(path, uri)
            }
            REQUEST_UPLOAD -> if (resultCode == RESULT_OK && uri != null) upload(uri)
        }
    }

    private fun displayName(uri: Uri): String? = contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (!it.moveToFirst()) null else it.getString(0)
    }

    private fun progress(done: Long, total: Long? = null) {
        if (done % (256 * 1024) > 32 * 1024 && total != done) return
        runOnUiThread {
            if (!disposed && busy) status.text = if (total == null) "Передано ${formatSize(done)}…"
            else "Скачано ${formatSize(done)} из ${formatSize(total)}…"
        }
    }

    private fun download(path: String, uri: Uri) {
        val opened = connection ?: return
        val requestId = generation
        cancelled.set(false)
        setBusy(true)
        status.text = "Скачиваем файл…"
        worker.execute {
            var staging: File? = null
            var success = false
            try {
                staging = File.createTempFile("sovagrid-sftp-", ".part", cacheDir)
                staging.outputStream().use { opened.download(path, it, cancelled::get, ::progress) }
                if (cancelled.get()) throw IOException("Cancelled")
                val source = staging
                (contentResolver.openOutputStream(uri, "w") ?: throw IOException("Destination unavailable")).use { output ->
                    source.inputStream().use { input ->
                        val buffer = ByteArray(32 * 1024)
                        while (true) {
                            if (cancelled.get()) throw IOException("Cancelled")
                            val count = input.read(buffer)
                            if (count < 0) break
                            output.write(buffer, 0, count)
                        }
                    }
                    output.flush()
                }
                if (cancelled.get()) throw IOException("Cancelled")
                success = true
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    status.text = "Файл сохранён через системное хранилище Android."
                    setBusy(false)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    if (cancelled.get() || !opened.isOpen) disconnect("Скачивание прервано. Неполный документ удалён, если это разрешило хранилище.")
                    else { status.text = "Скачивание не удалось (${error.javaClass.simpleName})."; setBusy(false) }
                }
            } finally {
                staging?.delete()
                if (!success) runCatching { DocumentsContract.deleteDocument(contentResolver, uri) }
            }
        }
    }

    private fun upload(uri: Uri) {
        val opened = connection ?: return
        val name = runCatching { displayName(uri) }.getOrNull()
        if (name == null || runCatching { RemotePath.child(directory, name) }.isFailure) {
            status.text = "Системный выбор вернул недопустимое имя файла."
            return
        }
        val requestId = generation
        val targetDirectory = directory
        cancelled.set(false)
        setBusy(true)
        status.text = "Загружаем $name…"
        worker.execute {
            try {
                (contentResolver.openInputStream(uri) ?: throw IOException("Document unavailable")).use { source ->
                    opened.upload(targetDirectory, name, source, cancelled::get) { progress(it) }
                }
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    setBusy(false)
                    status.text = "Файл $name загружен."
                    loadDirectory(targetDirectory)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (disposed || generation != requestId) return@runOnUiThread
                    if (cancelled.get() || !opened.isOpen) disconnect("Загрузка прервана. Временный файл на сервере очищен, если сервер доступен.")
                    else {
                        status.text = if (error.message == "Remote file already exists")
                            "На сервере уже есть $name. Переименуйте локальный файл перед загрузкой."
                        else "Загрузка не удалась (${error.javaClass.simpleName})."
                        setBusy(false)
                    }
                }
            }
        }
    }

    private fun cancelOperation() {
        cancelled.set(true)
        status.text = "Отменяем операцию…"
        connection?.let(::closeAsync)
    }

    private fun disconnect(message: String) {
        cancelled.set(true)
        generation++
        connection?.let(::closeAsync)
        connection = null
        selectedKey = null
        selectedGatewayKey = null
        busy = false
        showLogin(message)
    }

    private fun closeAsync(opened: SftpConnection) { Thread({ opened.close() }, "sovagrid-sftp-close").start() }

    override fun onStop() {
        super.onStop()
        if (pickerActive && connection != null) {
            val timeout = Runnable {
                if (pickerActive) {
                    cancelled.set(true)
                    generation++
                    connection?.let(::closeAsync)
                    connection = null
                }
            }
            pickerTimeout = timeout
            pickerHandler.postDelayed(timeout, 120_000)
        } else if (!pickerActive && connection != null) {
            disconnect("Соединение закрыто после ухода приложения в фон.")
        } else if (!pickerActive && busy) {
            cancelled.set(true)
            generation++
            busy = false
            showLogin("Подключение отменено после ухода приложения в фон.")
        }
    }

    override fun onDestroy() {
        disposed = true
        pickerTimeout?.let(pickerHandler::removeCallbacks)
        cancelled.set(true)
        connection?.let(::closeAsync)
        connection = null
        worker.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_KEY = 1401
        private const val REQUEST_GATEWAY_KEY = 1402
        private const val REQUEST_UPLOAD = 1403
        private const val REQUEST_DOWNLOAD = 1404
    }
}
