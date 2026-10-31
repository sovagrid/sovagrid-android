/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.text.InputType
import org.sovagrid.ssh.Authentication
import org.sovagrid.ssh.AuthenticationFailedException
import org.sovagrid.ssh.Endpoint
import org.sovagrid.ssh.HostKeyChangedException
import org.sovagrid.ssh.JumpHost
import org.sovagrid.ssh.ShellConnection
import org.sovagrid.ssh.SshClientCore
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import kotlin.math.roundToInt

class MainActivity : Activity() {
    private val hosts by lazy { HostStore(this) }
    private val ssh = SshClientCore()
    private val worker = Executors.newSingleThreadExecutor()
    private var currentServer: SavedServer? = null
    private var connection: ShellConnection? = null
    private var pendingFirstConnect: SessionSshCredential? = null
    private var firstPasswordDiscarded = false
    private var sessionHandoff: SessionSshHandoff? = null
    private var selectedKeyUri: Uri? = null
    private var selectedJumpKeyUri: Uri? = null
    @Volatile private var disposed = false
    private var probing = false
    private var screenGeneration = 0
    @Volatile private var connectionAttempt = 0
    private var terminalColumns = 80
    private var terminalRows = 24
    private var controlNext = false

    private lateinit var status: TextView
    private var terminalSurface: TerminalSurface? = null
    private lateinit var authControls: ScrollView
    private lateinit var passwordField: EditText
    private lateinit var passphraseField: EditText
    private lateinit var commandField: EditText
    private lateinit var keyButton: Button
    private var jumpPasswordField: EditText? = null
    private var jumpPassphraseField: EditText? = null
    private var jumpKeyButton: Button? = null
    private var jumpPasswordRadio: RadioButton? = null
    private var jumpKeyRadio: RadioButton? = null
    private var jumpProbeButton: Button? = null
    private var jumpResetButton: Button? = null
    private lateinit var connectButton: Button
    private lateinit var sendButton: Button
    private lateinit var probeButton: Button
    private lateinit var resetButton: Button
    private lateinit var passwordRadio: RadioButton
    private lateinit var keyRadio: RadioButton
    private lateinit var ctrlButton: Button
    private val terminalButtons = ArrayList<Button>()

    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        openRequestedServer(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        openRequestedServer(intent)
    }

    private fun openRequestedServer(intent: Intent) {
        val id = intent.getStringExtra("server_id")
        val server = if (id == null) null else runCatching { hosts.all().firstOrNull { it.id == id } }.getOrNull()
        if (server == null) showServerList() else showTerminal(server)
    }

    private fun Int.dp() = (this * resources.displayMetrics.density).roundToInt()

    private fun column(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(14.dp(), 14.dp(), 14.dp(), 14.dp())
    }

    private fun label(value: String, size: Float = 16f): TextView = TextView(this).apply {
        text = value
        textSize = size
        setPadding(0, 5.dp(), 0, 5.dp())
    }

    private fun input(hintText: String, isSecret: Boolean = false): EditText = EditText(this).apply {
        hint = hintText
        isSingleLine = true
        if (isSecret) {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
    }

    private fun showServerList() {
        screenGeneration++
        connectionAttempt++
        probing = false
        terminalSurface?.closeSurface()
        terminalSurface = null
        terminalButtons.clear()
        clearSecretFields()
        pendingFirstConnect?.clear()
        pendingFirstConnect = null
        firstPasswordDiscarded = false
        sessionHandoff?.clear()
        sessionHandoff = null
        currentServer = null
        selectedKeyUri = null
        selectedJumpKeyUri = null
        val old = connection
        connection = null
        if (old != null) worker.execute { old.close() }

        val root = column()
        root.addView(label("SovaGrid", 28f))
        root.addView(label("SSH-серверы", 19f))
        root.addView(Button(this).apply {
            text = "SSH-ключи: создать / публичный ключ"; isAllCaps = false
            setOnClickListener { startActivity(Intent(this@MainActivity, SshKeysActivity::class.java)) }
        })
        root.addView(Button(this).apply {
            text = "Тема: ${AppTheme.mode(this@MainActivity).label}"
            isAllCaps = false
            setOnClickListener { chooseTheme() }
        })
        root.addView(Button(this).apply {
            text = "О программе и лицензии"
            isAllCaps = false
            setOnClickListener { startActivity(Intent(this@MainActivity, AboutActivity::class.java)) }
        })
        root.addView(Button(this).apply {
            text = "Hub: мониторинг"
            setOnClickListener { startActivity(Intent(this@MainActivity, HubActivity::class.java)) }
        })
        root.addView(Button(this).apply {
            text = "Добавить сервер"
            setOnClickListener { showAddDialog() }
        })
        val saved = runCatching { hosts.all() }.getOrDefault(emptyList())
        if (saved.isEmpty()) root.addView(label("Пока нет серверов. Добавьте адрес, порт и пользователя."))
        saved.forEach { server ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            row.addView(Button(this).apply {
                text = "${server.label}\n${server.endpoint.username}@${server.endpoint.host}:${server.endpoint.port}" +
                    (server.jumpEndpoint?.let { " через ${it.username}@${it.host}:${it.port}" } ?: "")
                isAllCaps = false
                setOnClickListener { showTerminal(server) }
            }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            row.addView(Button(this).apply {
                text = "Удалить"
                setOnClickListener {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Удалить сервер?")
                        .setMessage("Адрес и доверенный ключ будут удалены.")
                        .setPositiveButton("Удалить") { _, _ ->
                            hosts.remove(server.id)
                            showServerList()
                        }
                        .setNegativeButton("Отмена", null)
                        .show()
                }
            })
            root.addView(row)
            root.addView(Button(this).apply {
                text = "Открыть панель через SSH"
                isAllCaps = false
                setOnClickListener {
                    startActivity(Intent(this@MainActivity, PanelActivity::class.java).putExtra("server_id", server.id))
                }
            })
            root.addView(Button(this).apply {
                text = "Файлы через SFTP"
                isAllCaps = false
                setOnClickListener {
                    startActivity(Intent(this@MainActivity, FilesActivity::class.java).putExtra("server_id", server.id))
                }
            })
        }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun chooseTheme() {
        val choices = ThemeMode.entries
        val selected = choices.indexOf(AppTheme.mode(this))
        AlertDialog.Builder(this)
            .setTitle("Тема приложения")
            .setSingleChoiceItems(choices.map { it.label }.toTypedArray(), selected) { dialog, index ->
                dialog.dismiss()
                val choice = choices[index]
                if (choice != AppTheme.mode(this)) {
                    AppTheme.choose(this, choice)
                    recreate()
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun showAddDialog() {
        val form = column()
        val name = input("Название, например Сервер")
        val host = input("Адрес или IP")
        val port = input("Порт SSH").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText("22")
        }
        val username = input("Пользователь")
        listOf(name, host, port, username).forEach { form.addView(it) }
        val firstPassword = input("SSH-пароль для первого входа (не сохраняется)", true)
        form.addView(firstPassword)
        val firstPasswordHelp = label("После проверки отпечатка сервера приложение подключится с этим паролем. Для входа по ключу оставьте поле пустым.")
        form.addView(firstPasswordHelp)
        val viaHost = CheckBox(this).apply { text = "Через промежуточный SSH-хост (ProxyJump)" }
        val jumpHost = input("IP или адрес промежуточного хоста")
        val jumpPort = input("SSH-порт промежуточного хоста").apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText("22")
        }
        val jumpUsername = input("Пользователь промежуточного хоста")
        listOf(viaHost, jumpHost, jumpPort, jumpUsername).forEach { form.addView(it) }
        viaHost.setOnCheckedChangeListener { _, enabled ->
            listOf(jumpHost, jumpPort, jumpUsername).forEach { it.visibility = if (enabled) View.VISIBLE else View.GONE }
            firstPassword.visibility = if (enabled) View.GONE else View.VISIBLE
            firstPasswordHelp.visibility = if (enabled) View.GONE else View.VISIBLE
            if (enabled) firstPassword.text?.clear()
        }
        listOf(jumpHost, jumpPort, jumpUsername).forEach { it.visibility = View.GONE }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Новый сервер")
            .setView(ScrollView(this).apply { addView(form) })
            .setPositiveButton("Открыть SSH", null)
            .setNegativeButton("Отмена", null)
            .create()
        dialog.setOnDismissListener { firstPassword.text?.clear() }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val endpoint = runCatching {
                    Endpoint(
                        host.text.toString().trim(),
                        port.text.toString().toInt(),
                        username.text.toString().trim()
                    )
                }.getOrNull()
                val gateway = if (viaHost.isChecked) runCatching {
                    Endpoint(jumpHost.text.toString().trim(), jumpPort.text.toString().toInt(), jumpUsername.text.toString().trim())
                }.getOrNull() else null
                if (endpoint == null || name.text.isBlank() || (viaHost.isChecked && gateway == null)) {
                    host.error = "Проверьте адрес, порт, пользователя и название"
                    return@setOnClickListener
                }
                val firstCredential = if (!viaHost.isChecked && firstPassword.text?.isNotEmpty() == true)
                    SessionSshCredential.Password(secret(firstPassword)) else null
                val server = hosts.add(name.text.toString(), endpoint, gateway)
                dialog.dismiss()
                showTerminal(server, firstCredential)
            }
        }
        dialog.show()
    }

    private fun showTerminal(server: SavedServer, firstCredential: SessionSshCredential? = null) {
        screenGeneration++
        connectionAttempt++
        probing = false
        clearSecretFields()
        pendingFirstConnect?.clear()
        pendingFirstConnect = firstCredential
        firstPasswordDiscarded = false
        sessionHandoff?.clear()
        sessionHandoff = null
        terminalSurface?.closeSurface()
        terminalSurface = null
        val staleConnection = connection
        connection = null
        if (staleConnection != null) worker.execute { staleConnection.close() }
        currentServer = server
        selectedKeyUri = null
        selectedJumpKeyUri = null
        controlNext = false
        terminalButtons.clear()
        terminalColumns = 80
        terminalRows = 24
        val root = column()
        root.addView(Button(this).apply {
            text = "← Серверы"
            setOnClickListener { showServerList() }
        })
        root.addView(label("${server.label} · ${server.endpoint.username}@${server.endpoint.host}:${server.endpoint.port}", 19f))
        server.jumpEndpoint?.let { root.addView(label("Через ${it.username}@${it.host}:${it.port} (SSH-переход)")) }
        status = label("Проверка доверия к серверу…")
        root.addView(status)
        val controls = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        jumpProbeButton = null
        jumpResetButton = null
        jumpPasswordField = null
        jumpPassphraseField = null
        jumpKeyButton = null
        jumpPasswordRadio = null
        jumpKeyRadio = null
        if (server.jumpEndpoint != null) {
            val gatewayTrustRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            jumpProbeButton = Button(this).apply {
                text = "Проверить ключ промежуточного узла"
                setOnClickListener { probeHost(server, gateway = true) }
            }
            jumpResetButton = Button(this).apply {
                text = "Сбросить ключ промежуточного узла"
                setOnClickListener { confirmResetPin(server, gateway = true) }
            }
            gatewayTrustRow.addView(jumpProbeButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            gatewayTrustRow.addView(jumpResetButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            controls.addView(gatewayTrustRow)

            controls.addView(label("Вход на промежуточный хост"))
            val gatewayMethods = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
            jumpPasswordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль промежуточного узла" }
            jumpKeyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Ключ промежуточного узла" }
            gatewayMethods.addView(jumpPasswordRadio)
            gatewayMethods.addView(jumpKeyRadio)
            gatewayMethods.check(jumpPasswordRadio!!.id)
            controls.addView(gatewayMethods)
            jumpPasswordField = input("SSH-пароль промежуточного хоста", true).also(controls::addView)
            jumpKeyButton = Button(this).apply {
                text = "Выбрать ключ промежуточного узла"
                setOnClickListener { choosePrivateKey(REQUEST_JUMP_PRIVATE_KEY) }
            }.also(controls::addView)
            jumpPassphraseField = input("Пароль ключа промежуточного узла (если есть)", true).also(controls::addView)
            gatewayMethods.setOnCheckedChangeListener { _, _ -> updateAuthFields() }
        }

        val trustRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        probeButton = Button(this).apply {
            text = if (server.jumpEndpoint == null) "Проверить ключ" else "Проверить ключ цели"
            setOnClickListener { probeHost(server, gateway = false) }
        }
        resetButton = Button(this).apply {
            text = if (server.jumpEndpoint == null) "Сбросить ключ" else "Сбросить ключ цели"
            setOnClickListener { confirmResetPin(server, gateway = false) }
        }
        trustRow.addView(probeButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        trustRow.addView(resetButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        controls.addView(trustRow)

        val methods = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        controls.addView(label("Вход на конечный сервер"))
        passwordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль" }
        keyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Приватный ключ" }
        methods.addView(passwordRadio)
        methods.addView(keyRadio)
        methods.check(passwordRadio.id)
        controls.addView(methods)
        passwordField = input("SSH-пароль", true)
        passphraseField = input("Пароль ключа (если есть)", true)
        keyButton = Button(this).apply {
            text = "Выбрать SSH-ключ"
            setOnClickListener { choosePrivateKey() }
        }
        controls.addView(passwordField)
        controls.addView(keyButton)
        controls.addView(passphraseField)
        methods.setOnCheckedChangeListener { _, _ -> updateAuthFields() }
        updateAuthFields()

        connectButton = Button(this).apply {
            text = "Подключиться"
            setOnClickListener { connect(server) }
        }
        controls.addView(connectButton)
        val controlsHeight = minOf(300.dp(), (resources.displayMetrics.heightPixels * 0.42f).roundToInt())
        authControls = ScrollView(this).apply { addView(controls) }
        root.addView(authControls, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, controlsHeight
        ))

        val surface = TerminalSurface(this,
            onInput = { sendTerminalInput(it) },
            onResize = { columns, rows -> resizeTerminal(columns, rows) },
            onFailure = {
                showTerminal(server)
                status.text = "Экран терминала перезапущен системой. Подключитесь снова."
            })
        terminalSurface = surface
        root.addView(surface, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
        ))

        val keyRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun key(title: String, data: String) = Button(this).apply {
            text = title
            isAllCaps = false
            setOnClickListener { sendTerminalInput(data) }
        }.also { keyRow.addView(it); terminalButtons.add(it) }
        key("Esc", "\u001b")
        key("Tab", "\t")
        ctrlButton = Button(this).apply {
            text = "Ctrl"
            isAllCaps = false
            setOnClickListener {
                controlNext = !controlNext
                text = if (controlNext) "Ctrl ✓" else "Ctrl"
            }
        }.also { keyRow.addView(it); terminalButtons.add(it) }
        key("←", "\u001b[D")
        key("↑", "\u001b[A")
        key("↓", "\u001b[B")
        key("→", "\u001b[C")
        key("↵", "\r")
        key("^C", "\u0003")
        key("^D", "\u0004")
        key("^Z", "\u001a")
        Button(this).apply {
            text = "Вставить"
            isAllCaps = false
            setOnClickListener { pasteClipboard() }
        }.also { keyRow.addView(it); terminalButtons.add(it) }
        root.addView(HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            addView(keyRow)
        })

        val commandRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        commandField = input("Команда или текст").apply {
            isEnabled = false
            imeOptions = EditorInfo.IME_ACTION_SEND
            setOnEditorActionListener { _, actionId, _ ->
                if (actionId == EditorInfo.IME_ACTION_SEND) {
                    sendCommand()
                    true
                } else false
            }
        }
        sendButton = Button(this).apply {
            text = "Отправить"
            isEnabled = false
            setOnClickListener { sendCommand() }
        }
        commandRow.addView(commandField, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        commandRow.addView(sendButton)
        root.addView(commandRow)
        terminalButtons.forEach { it.isEnabled = false }
        root.addView(Button(this).apply {
            text = "Отключиться"
            setOnClickListener { disconnectCurrent() }
        })
        root.addView(Button(this).apply {
            text = "Панель / установка SovaGrid через SSH"
            isAllCaps = false
            setOnClickListener {
                if (connection?.isOpen == true) {
                    sessionHandoff?.let {
                        EphemeralSshHandoff.offer(it)
                        sessionHandoff = null
                    }
                }
                startActivity(Intent(this@MainActivity, PanelActivity::class.java).putExtra("server_id", server.id))
            }
        })
        setContentView(root)

        updateTrustState(server)
        if (server.jumpEndpoint != null && hosts.pin(server.id, gateway = true) == null) {
            probeHost(server, gateway = true)
        } else if (server.jumpEndpoint == null && hosts.pin(server.id) == null) {
            probeHost(server, gateway = false)
        } else if (firstCredential != null && server.jumpEndpoint == null) {
            connectWithFirstCredential(server)
        }
        appendOutput("SovaGrid SSH · коснитесь экрана для клавиатуры; команды остаются в одной сессии.\r\n")
    }

    private fun updateAuthFields() {
        val useKey = keyRadio.isChecked
        if (useKey) passwordField.text?.clear() else passphraseField.text?.clear()
        passwordField.visibility = if (useKey) View.GONE else View.VISIBLE
        keyButton.visibility = if (useKey) View.VISIBLE else View.GONE
        passphraseField.visibility = if (useKey && !SshKeyPicker.internal(selectedKeyUri)) View.VISIBLE else View.GONE
        val useJumpKey = jumpKeyRadio?.isChecked == true
        if (useJumpKey) jumpPasswordField?.text?.clear() else jumpPassphraseField?.text?.clear()
        jumpPasswordField?.visibility = if (useJumpKey) View.GONE else View.VISIBLE
        jumpKeyButton?.visibility = if (useJumpKey) View.VISIBLE else View.GONE
        jumpPassphraseField?.visibility = if (useJumpKey && !SshKeyPicker.internal(selectedJumpKeyUri)) View.VISIBLE else View.GONE
    }

    private fun clearSecretFields() {
        if (::passwordField.isInitialized) passwordField.text?.clear()
        if (::passphraseField.isInitialized) passphraseField.text?.clear()
        jumpPasswordField?.text?.clear()
        jumpPassphraseField?.text?.clear()
    }

    private fun updateTrustState(server: SavedServer) {
        val gatewayTrusted = server.jumpEndpoint == null || hosts.pin(server.id, gateway = true) != null
        val destinationTrusted = hosts.pin(server.id) != null
        jumpProbeButton?.isEnabled = !probing && !gatewayTrusted
        jumpResetButton?.isEnabled = !probing && server.jumpEndpoint != null && gatewayTrusted
        probeButton.isEnabled = !probing && gatewayTrusted && !destinationTrusted
        resetButton.isEnabled = !probing && destinationTrusted
        connectButton.isEnabled = !probing && gatewayTrusted && destinationTrusted
        status.text = when {
            !gatewayTrusted -> "Сначала проверьте ключ промежуточного хоста."
            !destinationTrusted -> "Проверьте ключ конечного сервера. Для перехода потребуются учётные данные промежуточного узла."
            server.jumpEndpoint == null -> "Ключ сервера доверен. При подключении он будет проверен повторно."
            else -> "Оба ключа доверены. При подключении они будут проверены повторно."
        }
    }

    private fun gatewayCredentialsRequest(): SessionSshCredential? {
        if (jumpKeyRadio?.isChecked == true) {
            val uri = selectedJumpKeyUri
            if (uri == null) {
                status.text = "Сначала выберите приватный ключ промежуточного хоста."
                return null
            }
            return SessionSshCredential.Key(uri, secret(jumpPassphraseField!!))
        }
        return SessionSshCredential.Password(secret(jumpPasswordField!!))
    }

    private fun authentication(request: SessionSshCredential): Authentication = when (request) {
        is SessionSshCredential.Password -> Authentication.Password(request.chars)
        is SessionSshCredential.Key -> Authentication.PrivateKey(readKeyText(request.uri), request.passphrase)
    }

    private fun probeHost(server: SavedServer, gateway: Boolean) {
        if (probing || currentServer?.id != server.id || connection != null) return
        if (gateway && server.jumpEndpoint == null) return
        val gatewayPin = if (server.jumpEndpoint != null && !gateway) hosts.pin(server.id, gateway = true) else null
        if (server.jumpEndpoint != null && !gateway && gatewayPin == null) {
            status.text = "Сначала проверьте ключ промежуточного хоста."
            return
        }
        val request = if (server.jumpEndpoint != null && !gateway) gatewayCredentialsRequest() ?: return else null
        val checkedEndpoint = if (gateway) server.jumpEndpoint!! else server.endpoint
        val generation = screenGeneration
        probing = true
        probeButton.isEnabled = false
        jumpProbeButton?.isEnabled = false
        connectButton.isEnabled = false
        status.text = if (gateway) "Получаем ключ промежуточного хоста без передачи учётных данных…"
        else if (request != null) "Проверяем промежуточный узел и получаем ключ конечного сервера…"
        else "Получаем ключ сервера без передачи учётных данных…"
        worker.execute {
            try {
                val route = if (request != null) JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(request)) else null
                val observed = ssh.probe(checkedEndpoint, route)
                postUi {
                    if (screenGeneration != generation || currentServer?.id != server.id) return@postUi
                    probing = false
                    status.text = "Новый ключ: ${observed.fingerprintSha256}"
                    AlertDialog.Builder(this)
                        .setTitle(if (gateway) "Подтвердите ключ промежуточного узла" else "Подтвердите ключ сервера")
                        .setMessage(
                            "${checkedEndpoint.host}:${checkedEndpoint.port}\n" +
                                "Тип: ${observed.algorithm}\n" +
                                "${observed.fingerprintSha256}\n\n" +
                                "Сравните fingerprint с сервером через независимый канал. " +
                                if (gateway || request == null) "До подтверждения пароль и приватный ключ не отправляются."
                                else "Учётные данные конечного сервера до подтверждения не отправляются."
                        )
                        .setPositiveButton("Совпадает, доверять") { _, _ ->
                            if (hosts.setPin(server.id, observed.wireBase64, gateway)) {
                                status.text = "Ключ подтверждён: ${observed.fingerprintSha256}"
                                updateTrustState(server)
                                if (!gateway && server.jumpEndpoint == null) connectWithFirstCredential(server)
                            } else {
                                status.text = "Не удалось сохранить ключ; подключение заблокировано."
                                pendingFirstConnect?.clear()
                                pendingFirstConnect = null
                            }
                        }
                        .setNegativeButton("Отмена") { _, _ ->
                            status.text = "Ключ не подтверждён; подключение заблокировано."
                            pendingFirstConnect?.clear()
                            pendingFirstConnect = null
                            updateTrustState(server)
                        }
                        .setOnCancelListener {
                            status.text = "Ключ не подтверждён; подключение заблокировано."
                            pendingFirstConnect?.clear()
                            pendingFirstConnect = null
                            updateTrustState(server)
                        }
                        .show()
                }
            } catch (error: Exception) {
                postUi {
                    if (screenGeneration != generation || currentServer?.id != server.id) return@postUi
                    probing = false
                    pendingFirstConnect?.clear()
                    pendingFirstConnect = null
                    updateTrustState(server)
                    status.text = when (error) {
                        is HostKeyChangedException -> "Ключ промежуточного узла изменился. Вход заблокирован; проверьте его независимо."
                        is AuthenticationFailedException -> "Неверные учётные данные промежуточного хоста."
                        else -> "Не удалось получить ключ (${error.javaClass.simpleName}). Проверьте адрес, сеть и доступность туннеля."
                    }
                }
            } finally {
                request?.clear()
            }
        }
    }

    private fun confirmResetPin(server: SavedServer, gateway: Boolean) {
        if (connection != null) {
            status.text = "Сначала отключитесь."
            return
        }
        AlertDialog.Builder(this)
            .setTitle(if (gateway) "Сбросить доверенный ключ промежуточного узла?" else "Сбросить доверенный ключ сервера?")
            .setMessage("После сброса новый ключ потребуется проверить вне приложения. Используйте это только после проверки изменений на сервере.")
            .setPositiveButton("Сбросить") { _, _ ->
                if (hosts.setPin(server.id, null, gateway)) {
                    updateTrustState(server)
                    probeHost(server, gateway)
                }
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun choosePrivateKey(requestCode: Int = REQUEST_PRIVATE_KEY) = SshKeyPicker.choose(this, requestCode)

    @Deprecated("This small app uses the platform document picker directly.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK && requestCode == REQUEST_PRIVATE_KEY) {
            val uri = data?.data
            if (!hosts.recordKeySelection(currentServer?.id ?: return, uri?.let { SshKeyReference.id(it.toString()) })) {
                status.text = "Не удалось сохранить выбор ключа."; return
            }
            selectedKeyUri = uri; passphraseField.text.clear()
            keyButton.text = SshKeyPicker.description(this, uri)
            updateAuthFields()
        } else if (resultCode == RESULT_OK && requestCode == REQUEST_JUMP_PRIVATE_KEY) {
            val uri = data?.data
            if (!hosts.recordKeySelection(currentServer?.id ?: return, uri?.let { SshKeyReference.id(it.toString()) }, gateway = true)) {
                status.text = "Не удалось сохранить выбор ключа промежуточного узла."; return
            }
            selectedJumpKeyUri = uri; jumpPassphraseField?.text?.clear()
            jumpKeyButton?.text = SshKeyPicker.description(this, uri, gateway = true)
            updateAuthFields()
        }
    }

    private fun secret(field: EditText): CharArray {
        val value = field.text
        val chars = CharArray(value.length) { value[it] }
        value.clear()
        return chars
    }

    private fun connectWithFirstCredential(server: SavedServer) {
        val credential = pendingFirstConnect ?: return
        pendingFirstConnect = null
        if (currentServer?.id == server.id && hosts.pin(server.id) != null) connect(server, credential)
        else credential.clear()
    }

    private fun connect(server: SavedServer, firstCredential: SessionSshCredential? = null) {
        val pin = hosts.pin(server.id) ?: run { firstCredential?.clear(); return }
        val gatewayPin = if (server.jumpEndpoint != null)
            hosts.pin(server.id, gateway = true) ?: run { firstCredential?.clear(); return } else null
        if (connection != null || currentServer?.id != server.id) {
            firstCredential?.clear()
            return
        }
        val generation = screenGeneration
        val attempt = ++connectionAttempt
        val surface = terminalSurface ?: run { firstCredential?.clear(); return }
        val initialColumns = terminalColumns
        val initialRows = terminalRows
        val request = firstCredential ?: if (keyRadio.isChecked) {
            val uri = selectedKeyUri
            if (uri == null) {
                status.text = "Сначала выберите приватный ключ."
                return
            }
            SessionSshCredential.Key(uri, secret(passphraseField))
        } else SessionSshCredential.Password(secret(passwordField))
        val gatewayRequest = if (server.jumpEndpoint != null) gatewayCredentialsRequest() ?: run {
            request.clear()
            return
        } else null
        val reusable = SessionSshHandoff(server.id, request.duplicate(), gatewayRequest?.duplicate())
        connectButton.isEnabled = false
        status.text = "Подключаемся и проверяем сохранённые ключи…"
        worker.execute {
            try {
                val route = if (gatewayRequest != null) {
                    JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(gatewayRequest))
                } else null
                val opened = ssh.openShell(server.endpoint, pin, authentication(request),
                    onOutput = { text ->
                        if (connectionAttempt == attempt) surface.enqueueFromReader(text)
                    },
                    onClosed = {
                        postUi {
                            if (screenGeneration == generation && connectionAttempt == attempt &&
                                currentServer?.id == server.id && connection?.isOpen == false) {
                                connection = null
                                sessionHandoff?.clear()
                                sessionHandoff = null
                                status.text = "Сервер закрыл соединение."
                                connectButton.isEnabled = true
                                commandField.isEnabled = false
                                sendButton.isEnabled = false
                                terminalButtons.forEach { it.isEnabled = false }
                                controlNext = false
                                ctrlButton.text = "Ctrl"
                                authControls.visibility = View.VISIBLE
                            }
                        }
                    },
                    jump = route,
                    columns = initialColumns,
                    rows = initialRows
                )
                runOnUiThread {
                    if (disposed || screenGeneration != generation || connectionAttempt != attempt ||
                        currentServer?.id != server.id) {
                        closeAsync(opened)
                        reusable.clear()
                        return@runOnUiThread
                    }
                    // The shell can exit before this UI callback runs. In that case
                    // onClosed saw no connection yet, so restore the retry controls here.
                    if (!opened.isOpen) {
                        closeAsync(opened)
                        reusable.clear()
                        status.text = "Сервер закрыл соединение."
                        connectButton.isEnabled = true
                        commandField.isEnabled = false
                        sendButton.isEnabled = false
                        terminalButtons.forEach { it.isEnabled = false }
                        authControls.visibility = View.VISIBLE
                        return@runOnUiThread
                    }
                    connection = opened
                    sessionHandoff?.clear()
                    sessionHandoff = reusable
                    status.text = if (route == null) "Подключено. Ключ сервера совпал с сохранённым."
                    else "Подключено через промежуточный узел. Оба ключа совпали с сохранёнными."
                    commandField.isEnabled = true
                    sendButton.isEnabled = true
                    terminalButtons.forEach { it.isEnabled = true }
                    authControls.visibility = View.GONE
                    if (terminalColumns != initialColumns || terminalRows != initialRows) {
                        resizeTerminal(terminalColumns, terminalRows)
                    }
                    appendOutput("\r\n[SSH-сессия открыта]\r\n")
                }
            } catch (error: Exception) {
                reusable.clear()
                postUi {
                    if (screenGeneration != generation || connectionAttempt != attempt ||
                        currentServer?.id != server.id) return@postUi
                    when (error) {
                        is HostKeyChangedException -> {
                            val hop = if (error.endpoint == server.jumpEndpoint) "ПРОМЕЖУТОЧНОГО УЗЛА" else "СЕРВЕРА"
                            status.text = "КЛЮЧ $hop ИЗМЕНИЛСЯ. Вход заблокирован."
                            appendOutput("\nОжидался ${error.expectedFingerprint}\nПолучен ${error.presentedFingerprint}\n")
                            connectButton.isEnabled = false
                        }
                        is AuthenticationFailedException -> {
                            status.text = if (error.endpoint == server.jumpEndpoint) "Неверные учётные данные промежуточного узла."
                            else "Неверные учётные данные конечного сервера."
                            connectButton.isEnabled = true
                        }
                        else -> {
                            status.text = "Подключение не удалось (${error.javaClass.simpleName})."
                            connectButton.isEnabled = true
                        }
                    }
                }
            } finally {
                request.clear()
                gatewayRequest?.clear()
            }
        }
    }

    private fun readKeyText(uri: Uri): String = SshKeyPicker.read(this, uri)

    private fun sendCommand() {
        val command = commandField.text.toString()
        if (command.isEmpty()) return
        commandField.text.clear()
        if (controlNext && command.length == 1) {
            val control = TerminalKeys.control(command)
            if (control != null) {
                controlNext = false
                ctrlButton.text = "Ctrl"
                sendRaw(control)
                return
            }
        }
        controlNext = false
        ctrlButton.text = "Ctrl"
        sendRaw(command + "\r")
    }

    private fun sendTerminalInput(data: String) {
        if (data.isEmpty()) return
        val transformed = if (controlNext) TerminalKeys.control(data) else null
        if (controlNext) {
            controlNext = false
            ctrlButton.text = "Ctrl"
        }
        sendRaw(transformed ?: data)
    }

    private fun sendRaw(data: String) {
        val opened = connection ?: return
        worker.execute {
            try {
                opened.sendInput(data)
            } catch (_: Exception) {
                postUi {
                    if (connection === opened) {
                        status.text = "Не удалось отправить команду; соединение закрыто."
                        disconnectCurrent()
                    }
                }
            }
        }
    }

    private fun resizeTerminal(columns: Int, rows: Int) {
        if (columns == terminalColumns && rows == terminalRows) return
        terminalColumns = columns
        terminalRows = rows
        val opened = connection ?: return
        worker.execute {
            runCatching { opened.resize(columns, rows) }
        }
    }

    private fun pasteClipboard() {
        if (connection == null) return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val value = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
        if (value.isEmpty()) {
            status.text = "Буфер обмена пуст."
            return
        }
        if (value.length > 16_384) {
            status.text = "Для одной вставки допускается не более 16 384 символов."
            return
        }
        val action = { terminalSurface?.paste(value) }
        if ('\n' in value || '\r' in value) {
            AlertDialog.Builder(this)
                .setTitle("Вставить несколько строк?")
                .setMessage("Вставка нескольких строк может выполнить команды на сервере. Продолжить?")
                .setPositiveButton("Вставить") { _, _ -> action() }
                .setNegativeButton("Отмена", null)
                .show()
        } else action()
    }

    private fun disconnectCurrent() {
        val old = connection ?: return
        connectionAttempt++
        connection = null
        sessionHandoff?.clear()
        sessionHandoff = null
        commandField.isEnabled = false
        sendButton.isEnabled = false
        terminalButtons.forEach { it.isEnabled = false }
        controlNext = false
        ctrlButton.text = "Ctrl"
        val server = currentServer
        connectButton.isEnabled = server != null && hosts.pin(server.id) != null &&
            (server.jumpEndpoint == null || hosts.pin(server.id, gateway = true) != null)
        status.text = "Отключено."
        authControls.visibility = View.VISIBLE
        worker.execute { old.close() }
    }

    private fun appendOutput(chunk: String) {
        terminalSurface?.writeLocal(chunk)
    }

    private fun postUi(action: () -> Unit) {
        runOnUiThread { if (!disposed) action() }
    }

    private fun closeAsync(opened: ShellConnection) {
        if (!worker.isShutdown) worker.execute { opened.close() }
        else Thread { opened.close() }.start()
    }

    @Deprecated("Handled for API 26 compatibility")
    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        if (currentServer != null) showServerList() else super.onBackPressed()
    }

    override fun onDestroy() {
        disposed = true
        connectionAttempt++
        terminalSurface?.closeSurface()
        terminalSurface = null
        clearSecretFields()
        pendingFirstConnect?.clear()
        pendingFirstConnect = null
        sessionHandoff?.clear()
        sessionHandoff = null
        val old = connection
        connection = null
        worker.execute { old?.close() }
        worker.shutdown()
        super.onDestroy()
    }

    override fun onStop() {
        // PanelActivity consumes its one-time handoff in onCreate before this
        // onStop during normal in-app navigation. A still-pending value means
        // the app left the foreground before the handoff completed.
        EphemeralSshHandoff.clearPending()
        if (pendingFirstConnect != null) {
            pendingFirstConnect?.clear()
            pendingFirstConnect = null
            firstPasswordDiscarded = true
        }
        if (connection != null) disconnectCurrent()
        super.onStop()
    }

    override fun onStart() {
        super.onStart()
        if (firstPasswordDiscarded && currentServer != null && ::status.isInitialized) {
            status.text = "Пароль первого входа очищен при выходе из приложения. Введите его снова после проверки ключа."
            firstPasswordDiscarded = false
        }
    }

    companion object {
        private const val REQUEST_PRIVATE_KEY = 41
        private const val REQUEST_JUMP_PRIVATE_KEY = 42
    }
}
