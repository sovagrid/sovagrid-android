/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.Context
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.PersistableBundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import androidx.webkit.WebSettingsCompat
import org.json.JSONObject
import org.sovagrid.ssh.Authentication
import org.sovagrid.ssh.AuthenticationFailedException
import org.sovagrid.ssh.Endpoint
import org.sovagrid.ssh.HostKeyChangedException
import org.sovagrid.ssh.JumpHost
import org.sovagrid.ssh.LocalForwardConnection
import org.sovagrid.ssh.SshClientCore
import org.sovagrid.ssh.ServerDeployment
import org.sovagrid.ssh.ServerBootstrap
import org.sovagrid.ssh.ServerBootstrapException
import org.sovagrid.ssh.FirstInstallJob
import org.sovagrid.ssh.FirstInstallState
import java.io.ByteArrayOutputStream
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.Executors

/** The full Hub UI is loaded from the selected SSH host's loopback over verified SSH hops. */
class PanelActivity : Activity() {
    private val hosts by lazy { HostStore(this) }
    private val ssh = SshClientCore()
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var tunnel: LocalForwardConnection? = null
    private var browser: WebView? = null
    private val popups = mutableSetOf<WebView>()
    private var activeTunnelPort: Int? = null
    private var activePanelPath = "/sovagrid/monitoring/"
    private var bootstrapButton: Button? = null
    private var nativeGrantButton: Button? = null
    private var panelRetryButton: Button? = null
    private var bootstrapDialog: AlertDialog? = null
    private var bootstrapRequest = 0
    private var nativeGrantEligible = false
    private var nativeGrantAttempted = false
    private var nativeGrantRequest = 0
    private var nativePageGeneration = 0
    private var nativePageFailed = false
    private var panelRouteRefreshPending = false
    private var panelRouteRefreshRequest = 0
    private var panelRouteReloadURL: String? = null
    private var panelRouteReloadCount = 0
    private val clipboardHandler = Handler(Looper.getMainLooper())
    private var clipboardClearTask: Runnable? = null
    private var copiedPasswordDigest: ByteArray? = null
    private var pendingProfile: ProfileSaveRequest? = null
    private var profilePickerActive = false
    private var profileSaveInProgress = false
    private var selectedKeyUri: Uri? = null
    private var selectedGatewayKeyUri: Uri? = null
    private var initialHandoff: SessionSshHandoff? = null
    @Volatile private var activeHandoff: SessionSshHandoff? = null
    @Volatile private var disposed = false
    @Volatile private var visible = false
    private var opening = false
    private var probing = false
    private var routeGeneration = 0
    private var targetDestination = false

    private lateinit var server: SavedServer
    private lateinit var endpoint: Endpoint
    private var usesGatewayPin = false
    private lateinit var status: TextView
    private lateinit var connectButton: Button
    private lateinit var verifyButton: Button
    private lateinit var resetButton: Button
    private lateinit var passwordRadio: RadioButton
    private lateinit var keyRadio: RadioButton
    private lateinit var passwordField: EditText
    private lateinit var passphraseField: EditText
    private lateinit var keyButton: Button
    private lateinit var routeDescription: TextView
    private lateinit var authTitle: TextView
    private var routeChoices: RadioGroup? = null
    private var gatewayControls: LinearLayout? = null
    private var gatewayVerifyButton: Button? = null
    private var gatewayResetButton: Button? = null
    private var gatewayPasswordRadio: RadioButton? = null
    private var gatewayKeyRadio: RadioButton? = null
    private var gatewayPasswordField: EditText? = null
    private var gatewayPassphraseField: EditText? = null
    private var gatewayKeyButton: Button? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val id = intent.getStringExtra("server_id")
        val saved = runCatching { hosts.all().firstOrNull { it.id == id } }.getOrNull()
        if (saved == null) {
            finish()
            return
        }
        server = saved
        initialHandoff = EphemeralSshHandoff.take(saved.id)
        usesGatewayPin = saved.jumpEndpoint != null
        endpoint = saved.jumpEndpoint ?: saved.endpoint
        showLogin()
    }

    private fun showLogin() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 20, 20, 20)
        }
        root.addView(Button(this).apply {
            text = "← Серверы"
            setOnClickListener { finish() }
        })
        root.addView(TextView(this).apply {
            text = "Панель SovaGrid через SSH"
            textSize = 23f
        })
        routeDescription = TextView(this).apply {
            textSize = 15f
        }
        if (server.jumpEndpoint != null) {
            root.addView(TextView(this).apply {
                text = "Где запущен Hub?"
                textSize = 17f
            })
            val choices = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL }
            val onGateway = RadioButton(this).apply {
                id = View.generateViewId()
                text = "На промежуточном узле"
            }
            val onTarget = RadioButton(this).apply {
                id = View.generateViewId()
                text = "На конечном сервере через промежуточный узел"
            }
            choices.addView(onGateway)
            choices.addView(onTarget)
            choices.check(onGateway.id)
            choices.setOnCheckedChangeListener { _, selected ->
                if (opening || probing) return@setOnCheckedChangeListener
                targetDestination = selected == onTarget.id
                endpoint = if (targetDestination) server.endpoint else server.jumpEndpoint!!
                usesGatewayPin = !targetDestination
                routeGeneration++
                clearSecretFields()
                selectedKeyUri = null
                selectedGatewayKeyUri = null
                keyButton.text = "Выбрать SSH-ключ"
                gatewayKeyButton?.text = "Выбрать ключ промежуточного узла"
                updateRouteUi()
            }
            routeChoices = choices
            root.addView(choices)
        }
        root.addView(routeDescription)
        status = TextView(this).apply { textSize = 16f }
        root.addView(status)

        if (server.jumpEndpoint != null) {
            val gatewaySection = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            gatewaySection.addView(TextView(this).apply {
                text = "Вход на промежуточный узел для доступа к конечному серверу"
                textSize = 17f
            })
            gatewayVerifyButton = Button(this).apply {
                text = "Проверить ключ промежуточного узла"
                setOnClickListener { probeHost(gateway = true) }
            }.also(gatewaySection::addView)
            gatewayResetButton = Button(this).apply {
                text = "Сбросить доверие к ключу промежуточного узла"
                setOnClickListener { confirmResetPin(gateway = true) }
            }.also(gatewaySection::addView)
            val gatewayMethods = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
            gatewayPasswordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль промежуточного узла" }
            gatewayKeyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Ключ промежуточного узла" }
            gatewayMethods.addView(gatewayPasswordRadio)
            gatewayMethods.addView(gatewayKeyRadio)
            gatewayMethods.check(gatewayPasswordRadio!!.id)
            gatewaySection.addView(gatewayMethods)
            gatewayPasswordField = secretInput("SSH-пароль промежуточного узла").also(gatewaySection::addView)
            gatewayKeyButton = Button(this).apply {
                text = "Выбрать ключ промежуточного узла"
                setOnClickListener { choosePrivateKey(REQUEST_GATEWAY_PRIVATE_KEY) }
            }.also(gatewaySection::addView)
            gatewayPassphraseField = secretInput("Пароль ключа промежуточного узла (если есть)").also(gatewaySection::addView)
            gatewayMethods.setOnCheckedChangeListener { _, _ -> updateGatewayAuthFields() }
            gatewayControls = gatewaySection
            root.addView(gatewaySection)
        }

        verifyButton = Button(this).apply {
            text = "Проверить ключ SSH-хоста"
            setOnClickListener { probeHost() }
        }
        root.addView(verifyButton)
        resetButton = Button(this).apply {
            text = "Сбросить доверие к ключу SSH-хоста"
            setOnClickListener { confirmResetPin() }
        }
        root.addView(resetButton)

        authTitle = TextView(this).apply { textSize = 17f }
        root.addView(authTitle)
        val methods = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        passwordRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Пароль" }
        keyRadio = RadioButton(this).apply { id = View.generateViewId(); text = "Приватный ключ" }
        methods.addView(passwordRadio)
        methods.addView(keyRadio)
        methods.check(passwordRadio.id)
        root.addView(methods)
        passwordField = secretInput("SSH-пароль")
        passphraseField = secretInput("Пароль ключа (если есть)")
        keyButton = Button(this).apply {
            text = "Выбрать SSH-ключ"
            setOnClickListener { choosePrivateKey(REQUEST_PRIVATE_KEY) }
        }
        root.addView(passwordField)
        root.addView(keyButton)
        root.addView(passphraseField)
        methods.setOnCheckedChangeListener { _, _ -> updateAuthFields() }
        updateAuthFields()
        updateGatewayAuthFields()

        connectButton = Button(this).apply {
            text = "Открыть панель"
            setOnClickListener { openPanel() }
        }
        root.addView(connectButton)
        setContentView(ScrollView(this).apply { addView(root) })
        updateRouteUi()
    }

    private fun secretInput(hint: String) = EditText(this).apply {
        this.hint = hint
        isSingleLine = true
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun updateAuthFields() {
        val useKey = keyRadio.isChecked
        if (useKey) passwordField.text?.clear() else passphraseField.text?.clear()
        passwordField.visibility = if (useKey) View.GONE else View.VISIBLE
        keyButton.visibility = if (useKey) View.VISIBLE else View.GONE
        passphraseField.visibility = if (useKey && !SshKeyPicker.internal(selectedKeyUri)) View.VISIBLE else View.GONE
    }

    private fun updateGatewayAuthFields() {
        val useKey = gatewayKeyRadio?.isChecked == true
        if (useKey) gatewayPasswordField?.text?.clear() else gatewayPassphraseField?.text?.clear()
        gatewayPasswordField?.visibility = if (useKey) View.GONE else View.VISIBLE
        gatewayKeyButton?.visibility = if (useKey) View.VISIBLE else View.GONE
        gatewayPassphraseField?.visibility = if (useKey && !SshKeyPicker.internal(selectedGatewayKeyUri)) View.VISIBLE else View.GONE
    }

    private fun updateRouteUi() {
        gatewayControls?.visibility = if (targetDestination) View.VISIBLE else View.GONE
        val destination = if (targetDestination) "конечном сервере" else if (server.jumpEndpoint != null) "промежуточном узле" else "сервере"
        routeDescription.text = "${endpoint.username}@${endpoint.host}:${endpoint.port} → 127.0.0.1:8766 на $destination" +
            if (targetDestination) " (через ${server.jumpEndpoint!!.host})" else ""
        authTitle.text = if (targetDestination) "Вход на конечный сервер" else "Вход на SSH-хост"
        verifyButton.text = if (targetDestination) "Проверить ключ конечного сервера" else "Проверить ключ SSH-хоста"
        resetButton.text = if (targetDestination) "Сбросить доверие к ключу конечного сервера" else "Сбросить доверие к ключу SSH-хоста"
        updateTrustState()
    }

    private fun updateTrustState() {
        val gatewayTrusted = !targetDestination || hosts.pin(server.id, gateway = true) != null
        val targetTrusted = hosts.pin(server.id, usesGatewayPin) != null
        gatewayVerifyButton?.isEnabled = !probing && !opening && targetDestination && !gatewayTrusted
        gatewayResetButton?.isEnabled = !probing && !opening && targetDestination && gatewayTrusted
        verifyButton.isEnabled = !probing && !opening && gatewayTrusted && !targetTrusted
        resetButton.isEnabled = !probing && !opening && targetTrusted
        connectButton.isEnabled = !probing && !opening && gatewayTrusted && targetTrusted
        routeChoices?.let { choices ->
            for (index in 0 until choices.childCount) choices.getChildAt(index).isEnabled = !probing && !opening
        }
        status.text = when {
            !gatewayTrusted -> "Сначала сравните ключ промежуточного узла с независимым источником."
            !targetTrusted && targetDestination -> "Введите данные промежуточного узла, затем проверьте ключ конечного сервера независимо."
            !targetTrusted -> "Сравните ключ SSH-хоста с независимым источником."
            targetDestination -> "Ключи промежуточного и конечного узлов сохранены. При входе оба будут проверены повторно."
            else -> "Ключ SSH-хоста сохранён. При входе он будет проверен повторно."
        }
    }

    private fun confirmResetPin(gateway: Boolean = false) {
        if (probing || opening || tunnel != null) return
        val pinGateway = gateway || usesGatewayPin
        val target = if (gateway) "промежуточного узла" else if (targetDestination) "конечного сервера" else "SSH-хоста"
        AlertDialog.Builder(this)
            .setTitle("Сбросить доверие к ключу $target?")
            .setMessage("Новый ключ потребуется заново сравнить с независимым источником. Продолжайте только после проверки изменений на сервере.")
            .setPositiveButton("Сбросить") { _, _ ->
                if (hosts.setPin(server.id, null, pinGateway)) updateTrustState()
                else status.text = "Не удалось сбросить ключ."
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun probeHost(gateway: Boolean = false) {
        if (probing || opening) return
        val target = if (gateway) server.jumpEndpoint ?: return else endpoint
        val gatewayPin = if (targetDestination && !gateway) hosts.pin(server.id, gateway = true) ?: return else null
        val gatewayRequest = if (targetDestination && !gateway) gatewayCredentialsRequest() ?: return else null
        val generation = routeGeneration
        val pinGateway = gateway || usesGatewayPin
        probing = true
        updateTrustState()
        status.text = if (gateway || !targetDestination) "Получаем ключ без передачи учётных данных…"
        else "Проверяем промежуточный узел и получаем ключ конечного сервера без входа на него…"
        worker.execute {
            try {
                val jump = if (gatewayRequest != null)
                    JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(gatewayRequest)) else null
                val key = ssh.probe(target, jump)
                runOnUiThread {
                    if (disposed || isFinishing || generation != routeGeneration) return@runOnUiThread
                    probing = false
                    AlertDialog.Builder(this)
                        .setTitle(if (gateway) "Подтвердите ключ промежуточного узла" else if (targetDestination) "Подтвердите ключ конечного сервера" else "Подтвердите ключ SSH-хоста")
                        .setMessage("${target.host}:${target.port}\n${key.algorithm}\n${key.fingerprintSha256}\n\nСравните fingerprint через независимый канал.")
                        .setPositiveButton("Совпадает, доверять") { _, _ ->
                            if (generation != routeGeneration) return@setPositiveButton
                            if (hosts.setPin(server.id, key.wireBase64, pinGateway)) updateTrustState()
                            else status.text = "Не удалось сохранить ключ; вход заблокирован."
                        }
                        .setNegativeButton("Отмена") { _, _ -> updateTrustState() }
                        .setOnCancelListener { updateTrustState() }
                        .show()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (disposed || isFinishing || generation != routeGeneration) return@runOnUiThread
                    probing = false
                    updateTrustState()
                    status.text = when (error) {
                        is HostKeyChangedException -> "Ключ промежуточного узла изменился. Вход заблокирован; проверьте его независимо."
                        is AuthenticationFailedException -> "Неверные учётные данные промежуточного узла."
                        else -> "SSH-хост недоступен. Проверьте адрес, сеть и обратный туннель."
                    }
                }
            } finally {
                gatewayRequest?.clear()
            }
        }
    }

    private fun gatewayCredentialsRequest(): SessionSshCredential? {
        if (gatewayKeyRadio?.isChecked == true) {
            val uri = selectedGatewayKeyUri ?: run {
                status.text = "Сначала выберите приватный ключ промежуточного узла."
                return null
            }
            return SessionSshCredential.Key(uri, secret(gatewayPassphraseField!!))
        }
        return SessionSshCredential.Password(secret(gatewayPasswordField!!))
    }

    private fun authentication(request: SessionSshCredential): Authentication = when (request) {
        is SessionSshCredential.Password -> Authentication.Password(request.chars)
        is SessionSshCredential.Key -> Authentication.PrivateKey(readKeyText(request.uri), request.passphrase)
    }

    private fun choosePrivateKey(requestCode: Int) = SshKeyPicker.choose(this, requestCode)

    @Deprecated("The platform document picker is used on API 26+.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_PRIVATE_KEY && resultCode == RESULT_OK) {
            val uri = data?.data
            if (!hosts.recordKeySelection(server.id, uri?.let { SshKeyReference.id(it.toString()) }, gateway = usesGatewayPin)) {
                status.text = "Не удалось сохранить выбор ключа."; return
            }
            selectedKeyUri = uri; passphraseField.text.clear()
            keyButton.text = SshKeyPicker.description(this, uri)
            updateAuthFields()
        }
        if (requestCode == REQUEST_GATEWAY_PRIVATE_KEY && resultCode == RESULT_OK) {
            val uri = data?.data
            if (!hosts.recordKeySelection(server.id, uri?.let { SshKeyReference.id(it.toString()) }, gateway = true)) {
                status.text = "Не удалось сохранить выбор ключа промежуточного узла."; return
            }
            selectedGatewayKeyUri = uri; gatewayPassphraseField?.text?.clear()
            gatewayKeyButton?.text = SshKeyPicker.description(this, uri, gateway = true)
            updateGatewayAuthFields()
        }
        if (requestCode == REQUEST_SAVE_PROFILE) {
            profilePickerActive = false
            val profile = pendingProfile
            pendingProfile = null
            val destination = if (resultCode == RESULT_OK) data?.data?.takeIf { it.scheme == "content" } else null
            if (profile == null || destination == null) {
                profile?.bytes?.fill(0)
                finish()
                return
            }
            profileSaveInProgress = true
            worker.execute {
                val saved = try {
                    (contentResolver.openOutputStream(destination, "w") ?: throw IOException("Document not writable")).use {
                        it.write(profile.bytes)
                        it.flush()
                    }
                    true
                } catch (_: Exception) {
                    false
                } finally {
                    profile.bytes.fill(0)
                }
                runOnUiThread {
                    profileSaveInProgress = false
                    if (!disposed) {
                        Toast.makeText(this, if (saved) "VPN-профиль сохранён" else "Не удалось сохранить VPN-профиль", Toast.LENGTH_LONG).show()
                        finish()
                    }
                }
            }
        }
    }

    private fun secret(field: EditText): CharArray {
        val text = field.text
        val chars = CharArray(text.length) { text[it] }
        text.clear()
        return chars
    }

    private fun openPanel(preset: SessionSshHandoff? = null) {
        if (opening || probing) { preset?.clear(); return }
        val destination = endpoint
        val viaTarget = targetDestination
        val pin = hosts.pin(server.id, usesGatewayPin) ?: run { preset?.clear(); return }
        val gatewayPin = if (viaTarget) hosts.pin(server.id, gateway = true) ?: run {
            preset?.clear(); return
        } else null
        val handedOff = if (viaTarget || server.jumpEndpoint == null) preset?.target else preset?.gateway
        if (preset != null && handedOff == null) {
            preset.clear()
            status.text = "Данные SSH-сеанса недоступны. Введите их снова."
            return
        }
        val request = handedOff ?: if (keyRadio.isChecked) {
            val uri = selectedKeyUri ?: run {
                status.text = "Сначала выберите приватный ключ ${if (viaTarget) "конечного сервера" else "SSH-хоста"}."
                return
            }
            SessionSshCredential.Key(uri, secret(passphraseField))
        } else SessionSshCredential.Password(secret(passwordField))
        val gatewayRequest = if (viaTarget) (preset?.gateway ?: gatewayCredentialsRequest()) ?: run {
            request.clear()
            preset?.clear()
            return
        } else null
        activeHandoff = preset
        opening = true
        updateTrustState()
        status.text = if (viaTarget) "Проверяем ключи промежуточного и конечного узлов, открываем SSH-туннель…"
        else "Открываем защищённый SSH-туннель…"
        worker.execute {
            try {
                val jump = if (gatewayRequest != null)
                    JumpHost(server.jumpEndpoint!!, gatewayPin!!, authentication(gatewayRequest)) else null
                val opened = ssh.openHubPanel(destination, pin, authentication(request), jump)
                val installJob = opened.readFirstInstallJob()
                val deployment = runCatching { opened.readDeploymentStatus() }
                    .getOrDefault(ServerDeployment.UNKNOWN)
                val unknownHubHealthy = installJob.state == FirstInstallState.RUNNING ||
                    installJob.state == FirstInstallState.DONE || installJob.state == FirstInstallState.FAILED ||
                    deployment != ServerDeployment.UNKNOWN || opened.probeHubHealth()
                val panelPath = if (installJob.state !in listOf(FirstInstallState.RUNNING, FirstInstallState.FAILED) &&
                    (deployment == ServerDeployment.MANAGED ||
                        (deployment == ServerDeployment.UNKNOWN && unknownHubHealthy))) {
                    try { discoverPanelPath(opened.localPort) }
                    catch (error: IOException) { opened.close(); throw error }
                } else null
                runOnUiThread {
                    opening = false
                    if (disposed || isFinishing || !visible || !opened.isOpen) {
                        Thread({ opened.close() }, "sovagrid-close-panel").start()
                        return@runOnUiThread
                    }
                    if (installJob.state == FirstInstallState.RUNNING) {
                        tunnel = opened
                        observeFirstInstall(opened, installJob)
                        return@runOnUiThread
                    }
                    if (installJob.state == FirstInstallState.FAILED) {
                        Thread({ opened.close() }, "sovagrid-close-failed-install").start()
                        status.text = "Установка на сервере требует проверки"
                        AlertDialog.Builder(this).setTitle("Установка SovaGrid")
                            .setMessage(ServerBootstrap.failureText(installJob.reason))
                            .setPositiveButton("Закрыть", null).show()
                        updateTrustState()
                        return@runOnUiThread
                    }
                    if (installJob.state == FirstInstallState.DONE && deployment != ServerDeployment.MANAGED) {
                        tunnel = opened
                        showInstallJobFailure(opened,
                            "Установка завершилась, но управляемый Hub не подтверждён. Проверьте сервер.")
                        return@runOnUiThread
                    }
                    if (deployment == ServerDeployment.MISSING && destination.username == "root" &&
                        installJob.state == FirstInstallState.NONE) {
                        tunnel = opened
                        updateTrustState()
                        showDeploymentNotice(deployment, opened)
                        return@runOnUiThread
                    }
                    if (deployment != ServerDeployment.MANAGED && deployment != ServerDeployment.UNKNOWN) {
                        Thread({ opened.close() }, "sovagrid-close-panel").start()
                        updateTrustState()
                        showDeploymentNotice(deployment)
                        return@runOnUiThread
                    }
                    if (deployment == ServerDeployment.UNKNOWN && !unknownHubHealthy) {
                        Thread({ opened.close() }, "sovagrid-close-unavailable-panel").start()
                        status.text = "Панель на сервере недоступна"
                        updateTrustState()
                        AlertDialog.Builder(this).setTitle("Панель недоступна")
                            .setMessage("SSH-подключение установлено, но Hub на 127.0.0.1:8766 не отвечает. Проверьте состояние сервера и повторите вход.")
                            .setPositiveButton("Закрыть", null).show()
                        return@runOnUiThread
                    }
                    tunnel = opened
                    showBrowser(opened.localPort, deployment == ServerDeployment.MANAGED,
                        panelPath ?: "/sovagrid/monitoring/")
                }
            } catch (error: Exception) {
                runOnUiThread {
                    opening = false
                    if (disposed || isFinishing) return@runOnUiThread
                    status.text = when (error) {
                        is HostKeyChangedException -> {
                            val host = if (error.endpoint == server.jumpEndpoint) "промежуточного узла" else if (viaTarget) "конечного сервера" else "SSH-хоста"
                            "КЛЮЧ $host ИЗМЕНИЛСЯ. Вход заблокирован. Сбросьте ключ в профиле после проверки."
                        }
                        is AuthenticationFailedException -> {
                            val host = if (error.endpoint == server.jumpEndpoint) "промежуточного узла" else if (viaTarget) "конечного сервера" else "SSH-хоста"
                            "Неверные учётные данные $host."
                        }
                        is IOException -> "Не удалось подтвердить путь панели через SSH. Повторите подключение."
                        else -> "Не удалось открыть панель (${error.javaClass.simpleName})."
                    }
                    connectButton.isEnabled = error !is HostKeyChangedException
                    routeChoices?.let { choices ->
                        for (index in 0 until choices.childCount) choices.getChildAt(index).isEnabled = true
                    }
                }
            } finally {
                request.clear()
                gatewayRequest?.clear()
                preset?.clear()
                if (activeHandoff === preset) activeHandoff = null
            }
        }
    }

    private fun showDeploymentNotice(deployment: ServerDeployment, pendingInstall: LocalForwardConnection? = null) {
        val (title, detail) = when (deployment) {
            ServerDeployment.MISSING -> "SovaGrid ещё не установлен" to
                if (pendingInstall != null)
                    "Установить SovaGrid ${ServerBootstrap.VERSION} на ${endpoint.username}@${endpoint.host}? Сервер загрузит официальный пакет, сверит SHA-256 и повторно проверит, что на нём нет SovaGrid. Затем будут установлены Docker, локальные Hub и Agent. Установка может занять несколько минут. Панель откроется здесь после проверки."
                else "Для первой установки нужен вход root по SSH. Можно использовать SovaGrid Starter на компьютере."
            ServerDeployment.AGENT_ONLY -> "На сервере работает Agent" to
                "Здесь установлен только Agent. Полная установка поверх него могла бы затронуть существующий туннель и ключи. Для конечного сервера выберите «Hub на промежуточном узле»; перенос на самостоятельный Hub будет отдельной безопасной операцией."
            ServerDeployment.CONFLICT -> "Найдена неполная установка" to
                "На сервере заняты файлы или службы SovaGrid, но управляемый Hub не подтверждён. Автоматическая установка не запускается; проверьте состояние сервера в SovaGrid Connect."
            ServerDeployment.UNSUPPORTED -> "ОС пока не поддерживается" to
                "Установка серверной части сейчас поддерживается на Ubuntu. SSH-терминал и файлы можно использовать независимо от Hub."
            else -> return
        }
        status.text = title
        val builder = AlertDialog.Builder(this).setTitle(title).setMessage(detail)
            .setNegativeButton("Закрыть") { _, _ -> pendingInstall?.let(::discardPendingInstall) }
        if (deployment == ServerDeployment.MISSING) {
            if (pendingInstall != null) builder.setPositiveButton("Установить") { _, _ ->
                startFirstInstall(pendingInstall)
            }
            val openStarter = android.content.DialogInterface.OnClickListener { _, _ ->
                pendingInstall?.let(::discardPendingInstall)
                try {
                    startActivity(Intent(Intent.ACTION_VIEW,
                        Uri.parse("https://github.com/sovagrid/sovagrid-blueprint/releases/tag/server-v0.11.0")))
                } catch (_: ActivityNotFoundException) {
                    Toast.makeText(this, "Не удалось открыть страницу загрузки", Toast.LENGTH_LONG).show()
                }
            }
            if (pendingInstall != null) builder.setNeutralButton("Starter", openStarter)
            else builder.setPositiveButton("Открыть Starter", openStarter)
        }
        builder.setOnCancelListener { pendingInstall?.let(::discardPendingInstall) }.show()
    }

    private fun discardPendingInstall(opened: LocalForwardConnection) {
        if (tunnel === opened) tunnel = null
        Thread({ opened.close() }, "sovagrid-close-install-prompt").start()
        if (!disposed && !isFinishing) updateTrustState()
    }

    private fun startFirstInstall(opened: LocalForwardConnection) {
        if (disposed || !visible || tunnel !== opened || !opened.isOpen || opening) {
            discardPendingInstall(opened)
            return
        }
        opening = true
        status.text = "Проверяем сервер перед установкой…"
        updateTrustState()
        worker.execute {
            try {
                val started = opened.startDetachedInstall()
                runOnUiThread {
                    if (disposed || isFinishing || !visible || tunnel !== opened || !opened.isOpen) {
                        discardPendingInstall(opened)
                        return@runOnUiThread
                    }
                    observeFirstInstall(opened, started)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    opening = false
                    if (disposed || isFinishing || tunnel !== opened) return@runOnUiThread
                    discardPendingInstall(opened)
                    status.text = "Установка не завершилась"
                    AlertDialog.Builder(this).setTitle("Установка SovaGrid")
                        .setMessage((error as? ServerBootstrapException)?.message ?:
                            "Сервер не подтвердил результат установки. Проверьте подключение и состояние сервера в SSH-терминале перед повторением.")
                        .setPositiveButton("Закрыть", null).show()
                }
            }
        }
    }

    private fun observeFirstInstall(opened: LocalForwardConnection, initial: FirstInstallJob) {
        if (tunnel !== opened || !visible) return
        opening = true
        status.text = ServerBootstrap.stageText(initial.stage)
        updateTrustState()
        worker.execute {
            var job = initial
            while (visible && !disposed && opened.isOpen && tunnel === opened) {
                when (job.state) {
                    FirstInstallState.RUNNING -> {
                        val message = ServerBootstrap.stageText(job.stage)
                        runOnUiThread { if (visible && tunnel === opened) status.text = message }
                        Thread.sleep(2_000)
                        job = opened.readFirstInstallJob()
                    }
                    FirstInstallState.DONE -> {
                        val managed = opened.readDeploymentStatus() == ServerDeployment.MANAGED
                        val panelPath = if (managed) runCatching { discoverPanelPath(opened.localPort) }.getOrNull() else null
                        runOnUiThread {
                            opening = false
                            if (visible && tunnel === opened && managed && panelPath != null)
                                showBrowser(opened.localPort, managed = true, panelPath = panelPath)
                            else if (visible && tunnel === opened) showInstallJobFailure(opened,
                                "Установка завершилась, но путь панели не подтверждён. Проверьте сервер.")
                        }
                        return@execute
                    }
                    FirstInstallState.FAILED -> {
                        val message = ServerBootstrap.failureText(job.reason)
                        runOnUiThread { if (visible && tunnel === opened) showInstallJobFailure(opened, message) }
                        return@execute
                    }
                    else -> {
                        runOnUiThread { if (visible && tunnel === opened) showInstallJobFailure(opened,
                            "Состояние установки недоступно. Проверьте сервер перед повторением.") }
                        return@execute
                    }
                }
            }
        }
    }

    private fun showInstallJobFailure(opened: LocalForwardConnection, message: String) {
        opening = false
        discardPendingInstall(opened)
        status.text = "Установка на сервере требует проверки"
        AlertDialog.Builder(this).setTitle("Установка SovaGrid")
            .setMessage(message).setPositiveButton("Закрыть", null).show()
    }

    private fun readKeyText(uri: Uri): String = SshKeyPicker.read(this, uri)

    private data class PanelHTTP(val status: Int, val mime: String, val body: ByteArray)

    private fun panelGet(port: Int, path: String, limit: Int): PanelHTTP {
        val target = URL("http://127.0.0.1:$port$path")
        val connection = target.openConnection(Proxy.NO_PROXY) as HttpURLConnection
        return try {
            connection.connectTimeout = 1_500
            connection.readTimeout = 1_500
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = "GET"
            val status = connection.responseCode
            val bytes = if (status == HttpURLConnection.HTTP_OK) {
                connection.inputStream.use { input ->
                    val output = ByteArrayOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (output.size() + count > limit) throw IOException("Ответ панели слишком велик")
                        output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
            } else ByteArray(0)
            PanelHTTP(status, connection.contentType ?: "", bytes)
        } finally { connection.disconnect() }
    }

    private fun validPanelPath(path: String): Boolean =
        path.length <= 96 &&
            Regex("^/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}$").matches(path) &&
            path.split('/').getOrNull(1) !in listOf("api", "healthz")

    private fun verifiedPanelPath(port: Int, path: String): Boolean = try {
        val page = panelGet(port, path, 262_144)
        if (page.status != HttpURLConnection.HTTP_OK || !page.mime.startsWith("text/html") ||
            !String(page.body, StandardCharsets.UTF_8).contains("SovaGrid")) false
        else {
            val manifest = panelGet(port, path + "manifest.webmanifest", 8192)
            manifest.status == HttpURLConnection.HTTP_OK &&
                manifest.mime.startsWith("application/manifest+json") &&
                JSONObject(String(manifest.body, StandardCharsets.UTF_8)).optString("name").contains("SovaGrid")
        }
    } catch (_: Exception) { false }

    private fun discoverPanelPath(port: Int): String {
        val deadline = System.nanoTime() + 20_000_000_000L
        while (System.nanoTime() < deadline) {
            val response = try { panelGet(port, "/api/v1/panel-location", 512) }
                catch (_: IOException) { null }
            val paths = when (response?.status) {
                HttpURLConnection.HTTP_NOT_FOUND -> listOf("/sovagrid/monitoring/", "/")
                HttpURLConnection.HTTP_UNAVAILABLE -> emptyList()
                HttpURLConnection.HTTP_OK -> {
                    val value = try { JSONObject(String(response.body, StandardCharsets.UTF_8)) }
                        catch (_: Exception) { throw IOException("Неверный ответ с адресом панели") }
                    val path = value.optString("panel_path")
                    if (value.length() != 1 || !validPanelPath(path))
                        throw IOException("Неверный путь панели")
                    listOf(path)
                }
                null -> emptyList()
                else -> throw IOException("Путь панели недоступен")
            }
            for (path in paths) if (verifiedPanelPath(port, path)) return path
            Thread.sleep(300)
        }
        throw IOException("Путь панели не подтверждён")
    }

    private fun panelHome(port: Int): String = "http://127.0.0.1:$port$activePanelPath"

    private fun showBrowser(port: Int, managed: Boolean, panelPath: String) {
        activePanelPath = panelPath
        panelRouteRefreshPending = false
        panelRouteRefreshRequest++
        panelRouteReloadURL = null
        panelRouteReloadCount = 0
        clearSecretFields()
        selectedKeyUri = null
        nativeGrantEligible = managed
        nativeGrantAttempted = false
        val panelOrigin = "http://127.0.0.1:$port"
        val panelURL = panelHome(port)
        activeTunnelPort = port
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        layout.addView(Button(this).apply {
            text = "← Закрыть панель и SSH-туннель"
            setOnClickListener { finish() }
        })
        val view = WebView(this).apply {
            setBackgroundColor(if (AppTheme.isDark(this@PanelActivity)) Color.rgb(14, 23, 37) else Color.WHITE)
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            if (WebViewFeature.isFeatureSupported(WebViewFeature.ALGORITHMIC_DARKENING)) {
                WebSettingsCompat.setAlgorithmicDarkeningAllowed(settings, AppTheme.isDark(this@PanelActivity))
            }
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
            settings.setSupportMultipleWindows(true)
            webChromeClient = object : WebChromeClient() {
                override fun onCreateWindow(view: WebView, isDialog: Boolean,
                                            isUserGesture: Boolean, resultMsg: Message): Boolean {
                    if (!isUserGesture || view !== browser || !panelReady(port)) return false
                    val transport = resultMsg.obj as? WebView.WebViewTransport ?: return false
                    val popup = WebView(this@PanelActivity).apply {
                        settings.javaScriptEnabled = false
                        settings.domStorageEnabled = false
                        settings.allowFileAccess = false
                        settings.allowContentAccess = false
                        settings.blockNetworkLoads = true
                        webViewClient = object : WebViewClient() {
                            override fun shouldOverrideUrlLoading(view: WebView,
                                                                  request: WebResourceRequest): Boolean {
                                // onCreateWindow already required the original tap gesture.
                                if (request.isForMainFrame) {
                                    openTelegramLink(request.url.toString(), port)
                                }
                                view.post { disposePopup(view) }
                                return true
                            }

                            override fun shouldInterceptRequest(view: WebView,
                                                                request: WebResourceRequest): WebResourceResponse =
                                WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream(ByteArray(0)))

                            override fun onPageStarted(view: WebView, url: String,
                                                       favicon: android.graphics.Bitmap?) {
                                if (url != "about:blank") view.stopLoading()
                            }
                        }
                    }
                    popups.add(popup)
                    transport.webView = popup
                    resultMsg.sendToTarget()
                    popup.postDelayed({ disposePopup(popup) }, 5000)
                    return true
                }
            }
            webViewClient = object : WebViewClient() {
                private fun allowed(uri: Uri): Boolean =
                    uri.scheme == "http" && uri.host == "127.0.0.1" && uri.port == port

                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    if (allowed(request.url)) return false
                    if (request.isForMainFrame && request.hasGesture()) {
                        openTelegramLink(request.url.toString(), port)
                    }
                    return true
                }

                override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                    nativePageGeneration++
                    nativePageFailed = false
                    nativeGrantButton?.isEnabled = false
                    panelRetryButton?.visibility = View.GONE
                    if (!allowed(Uri.parse(url))) {
                        view.stopLoading()
                        finish()
                    }
                }

                override fun onReceivedHttpError(view: WebView, request: WebResourceRequest,
                                                 errorResponse: WebResourceResponse) {
                    if (request.isForMainFrame) nativePageFailed = true
                }

                override fun onReceivedError(view: WebView, request: WebResourceRequest,
                                             error: WebResourceError) {
                    if (request.isForMainFrame) nativePageFailed = true
                }

                override fun onPageFinished(view: WebView, url: String) {
                    bootstrapButton?.isEnabled = panelReady(port) && !nativePageFailed
                    nativeGrantButton?.isEnabled = managed && panelReady(port) &&
                        !nativePageFailed && url == panelHome(port)
                    if (managed && (nativePageFailed || url != panelHome(port))) {
                        refreshPanelRouteAfterNavigation(port, view, url, nativePageFailed)
                    } else {
                        panelRetryButton?.visibility = View.GONE
                        panelRouteReloadURL = null
                        panelRouteReloadCount = 0
                        requestNativeGrantIfReady(port, view, url)
                    }
                }

                override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                    if (allowed(request.url)) null
                    else WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream(ByteArray(0)))
            }
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(view, "sovagridNativeProfile", setOf(panelOrigin)) {
                    sourceView, message, sourceOrigin, isMainFrame, _ ->
                acceptProfileMessage(sourceView, message.data, sourceOrigin, isMainFrame, port)
            }
        }
        browser = view
        bootstrapButton = Button(this).apply {
            text = "Получить начальный пароль Hub"
            isEnabled = false
            setOnClickListener { fetchBootstrapPassword(port) }
        }
        layout.addView(bootstrapButton)
        nativeGrantButton = Button(this).apply {
            text = "Войти через SSH"
            isEnabled = false
            visibility = if (managed) View.VISIBLE else View.GONE
            setOnClickListener {
                if (!panelReady(port)) return@setOnClickListener
                nativeGrantAttempted = false
                requestNativeGrantIfReady(port, view, view.url ?: return@setOnClickListener)
            }
        }
        layout.addView(nativeGrantButton)
        panelRetryButton = Button(this).apply {
            text = "Повторить загрузку панели"
            visibility = View.GONE
            setOnClickListener {
                if (!panelReady(port)) return@setOnClickListener
                val loaded = view.url ?: return@setOnClickListener
                panelRouteReloadURL = null
                panelRouteReloadCount = 0
                refreshPanelRouteAfterNavigation(port, view, loaded, nativePageFailed)
            }
        }
        layout.addView(panelRetryButton)
        layout.addView(view, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(layout)
        view.loadUrl(panelURL)
    }

    /** Rebind an SSH grant only after Hub and the served page agree on the new route. */
    private fun refreshPanelRouteAfterNavigation(port: Int, view: WebView, loadedUrl: String,
                                                  failedPage: Boolean) {
        if (panelRouteRefreshPending || browser !== view || !panelReady(port) ||
            Uri.parse(loadedUrl).let { it.scheme != "http" || it.host != "127.0.0.1" ||
                it.port != port || (!failedPage && it.toString() == panelHome(port)) }) return
        val opened = tunnel ?: return
        panelRouteRefreshPending = true
        nativeGrantButton?.isEnabled = false
        panelRetryButton?.apply {
            text = "Проверяем путь панели…"
            visibility = View.VISIBLE
            isEnabled = false
        }
        val request = ++panelRouteRefreshRequest
        val page = nativePageGeneration
        worker.execute {
            val discovered = runCatching { discoverPanelPath(port) }.getOrNull()
            runOnUiThread {
                if (request != panelRouteRefreshRequest) return@runOnUiThread
                panelRouteRefreshPending = false
                if (disposed || isFinishing || !visible || opened !== tunnel ||
                    browser !== view || !panelReady(port)) return@runOnUiThread
                val currentUrl = view.url ?: return@runOnUiThread
                if (page != nativePageGeneration) {
                    if (nativePageFailed || currentUrl != panelHome(port))
                        refreshPanelRouteAfterNavigation(port, view, currentUrl, nativePageFailed)
                    else panelRetryButton?.visibility = View.GONE
                    return@runOnUiThread
                }
                if (currentUrl != loadedUrl) {
                    if (nativePageFailed || currentUrl != panelHome(port))
                        refreshPanelRouteAfterNavigation(port, view, currentUrl, nativePageFailed)
                    else panelRetryButton?.visibility = View.GONE
                    return@runOnUiThread
                }
                if (discovered == null) {
                    offerPanelRetry()
                    return@runOnUiThread
                }
                val confirmedURL = "http://127.0.0.1:$port$discovered"
                if (!failedPage && currentUrl != confirmedURL) {
                    offerPanelRetry()
                    return@runOnUiThread
                }
                activePanelPath = discovered
                nativeGrantAttempted = false
                if (failedPage) {
                    // Discovery checks the now-healthy page and manifest, but
                    // WebView still holds the old 404/503/error document.
                    if (currentUrl != confirmedURL) {
                        panelRouteReloadURL = null
                        panelRouteReloadCount = 0
                        view.loadUrl(confirmedURL)
                    } else {
                        if (panelRouteReloadURL != confirmedURL) {
                            panelRouteReloadURL = confirmedURL
                            panelRouteReloadCount = 0
                        }
                        if (panelRouteReloadCount++ < 2) view.loadUrl(confirmedURL)
                        else offerPanelRetry()
                    }
                    return@runOnUiThread
                }
                panelRetryButton?.visibility = View.GONE
                nativeGrantButton?.isEnabled = true
                requestNativeGrantIfReady(port, view, currentUrl)
            }
        }
    }

    private fun offerPanelRetry() {
        nativeGrantButton?.isEnabled = false
        panelRetryButton?.apply {
            text = "Повторить загрузку панели"
            visibility = View.VISIBLE
            isEnabled = true
        }
    }

    private fun requestNativeGrantIfReady(port: Int, view: WebView, loadedUrl: String) {
        val panelURL = panelHome(port)
        val isPanelHome = { url: String? -> url == panelURL }
        if (!nativeGrantEligible || nativeGrantAttempted || nativePageFailed || !isPanelHome(loadedUrl) ||
            browser !== view || !isPanelHome(view.url) || !panelReady(port)) return
        val opened = tunnel ?: return
        nativeGrantAttempted = true
        nativeGrantButton?.isEnabled = false
        val request = ++nativeGrantRequest
        val page = nativePageGeneration
        worker.execute {
            val grant = runCatching { opened.readSSHGrantResponse()?.let(SshGrantProtocol::parse) }.getOrNull()
            runOnUiThread {
                if (request == nativeGrantRequest && browser === view && panelReady(port) &&
                    view.url == panelURL) {
                    nativeGrantButton?.isEnabled = true
                }
                if (request != nativeGrantRequest || page != nativePageGeneration ||
                    disposed || isFinishing || !visible || opened !== tunnel ||
                    browser !== view || !isPanelHome(view.url) || !panelReady(port) || grant == null) return@runOnUiThread
                // The grant enters only this verified loopback origin as a JSON string literal.
                // The page sends it in a POST body and keeps the resulting session in memory.
                runCatching {
                    view.evaluateJavascript(
                        "globalThis.sovagridRedeemNativeSSHGrant(${JSONObject.quote(grant)})", null
                    )
                }
            }
        }
    }

    private fun panelReady(port: Int): Boolean {
        if (!visible || disposed || isFinishing || activeTunnelPort != port || tunnel?.isOpen != true) return false
        val loaded = browser?.url ?: return false
        val uri = Uri.parse(loaded)
        return uri.scheme == "http" && uri.host == "127.0.0.1" && uri.port == port
    }

    private fun fetchBootstrapPassword(port: Int) {
        if (!panelReady(port)) return
        val opened = tunnel ?: return
        val request = ++bootstrapRequest
        bootstrapButton?.isEnabled = false
        nativeGrantButton?.isEnabled = false
        worker.execute {
            val password = try { opened.readBootstrapPassword() } catch (_: Exception) { null }
            runOnUiThread {
                if (request != bootstrapRequest || opened !== tunnel || !panelReady(port)) {
                    password?.fill('\u0000')
                    return@runOnUiThread
                }
                bootstrapButton?.isEnabled = true
                if (password == null) {
                    Toast.makeText(this,
                        "Нет доступа к начальному паролю. Подключитесь SSH-пользователем с правом чтения файла (обычно root).",
                        Toast.LENGTH_LONG).show()
                } else {
                    showBootstrapPassword(password, port)
                }
            }
        }
    }

    private fun showBootstrapPassword(password: CharArray, port: Int) {
        bootstrapDialog?.dismiss()
        val dialog = AlertDialog.Builder(this)
            .setTitle("Начальный пароль Hub")
            .setMessage("Пароль: ••••••••••••••••••••\n\nНажмите «Копировать», затем войдите как admin в панели. " +
                "После смены пароля в «Настройках» этот начальный пароль устареет.")
            .setPositiveButton("Копировать", null)
            .setNegativeButton("Закрыть", null)
            .create()
        bootstrapDialog = dialog
        dialog.setOnDismissListener {
            password.fill('\u0000')
            if (bootstrapDialog === dialog) bootstrapDialog = null
        }
        dialog.show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if (panelReady(port)) {
                copyBootstrapPassword(password)
                Toast.makeText(this, "Пароль скопирован на 60 секунд", Toast.LENGTH_SHORT).show()
            }
            dialog.dismiss()
        }
    }

    private fun copyBootstrapPassword(password: CharArray) {
        clearCopiedPassword()
        val secret = String(password)
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("SovaGrid Hub", secret)
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        clipboard.setPrimaryClip(clip)
        val utf8 = secret.toByteArray(StandardCharsets.UTF_8)
        try {
            copiedPasswordDigest = MessageDigest.getInstance("SHA-256").digest(utf8)
        } finally {
            utf8.fill(0)
        }
        val task = Runnable { clearCopiedPassword() }
        clipboardClearTask = task
        clipboardHandler.postDelayed(task, 60_000)
    }

    private fun clearCopiedPassword(forceIfUnreadable: Boolean = false) {
        clipboardClearTask?.let(clipboardHandler::removeCallbacks)
        clipboardClearTask = null
        val expected = copiedPasswordDigest ?: return
        copiedPasswordDigest = null
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        var couldRead = false
        try {
            val clip = clipboard.primaryClip
            if (clip?.itemCount == 1) {
                couldRead = true
                val text = clip.getItemAt(0).text?.toString()
                if (text != null) {
                    val bytes = text.toByteArray(StandardCharsets.UTF_8)
                    try {
                        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
                        if (MessageDigest.isEqual(expected, actual)) {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                        actual.fill(0)
                    } finally {
                        bytes.fill(0)
                    }
                }
            }
        } catch (_: Exception) {
            // Clipboard access may be unavailable after the app moves to background.
        } finally {
            if (forceIfUnreadable && !couldRead) {
                runCatching { clipboard.setPrimaryClip(ClipData.newPlainText("", "")) }
            }
            expected.fill(0)
        }
    }

    private fun openTelegramLink(rawUrl: String, port: Int) {
        if (!panelReady(port)) return
        val url = TelegramLinkPolicy.externalUrl(rawUrl) ?: return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
            })
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "Не найдено приложение для ссылки Telegram", Toast.LENGTH_LONG).show()
        } catch (_: SecurityException) {
            Toast.makeText(this, "Не удалось открыть ссылку Telegram", Toast.LENGTH_LONG).show()
        }
    }

    private fun acceptProfileMessage(sourceView: WebView, raw: String?, sourceOrigin: Uri,
                                     isMainFrame: Boolean, port: Int) {
        if (!isMainFrame || sourceView !== browser || !visible || disposed || isFinishing ||
            tunnel?.isOpen != true || activeTunnelPort != port ||
            profilePickerActive || profileSaveInProgress || pendingProfile != null ||
            sourceOrigin.scheme != "http" || sourceOrigin.authority != "127.0.0.1:$port" ||
            sourceOrigin.path !in listOf(null, "", "/") || sourceOrigin.query != null || sourceOrigin.fragment != null ||
            sourceView.url?.let { url ->
                val loaded = Uri.parse(url)
                loaded.scheme == "http" && loaded.host == "127.0.0.1" && loaded.port == port
            } != true || raw == null || raw.length > MAX_PROFILE_MESSAGE_LENGTH) return

        val profile = try {
            val json = JSONObject(raw)
            if (json.length() != 3 || !json.has("version") || !json.has("filename") || !json.has("data")) null
            else ProfileSaveContract.decode(json.opt("version"), json.opt("filename"), json.opt("data"))
        } catch (_: Exception) {
            null
        } ?: return

        pendingProfile = profile
        profilePickerActive = true
        try {
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_TITLE, profile.filename)
            }, REQUEST_SAVE_PROFILE)
        } catch (_: Exception) {
            profilePickerActive = false
            pendingProfile = null
            profile.bytes.fill(0)
            Toast.makeText(this, "Системный выбор файла недоступен", Toast.LENGTH_LONG).show()
        }
    }

    private fun clearSecretFields() {
        if (::passwordField.isInitialized) passwordField.text?.clear()
        if (::passphraseField.isInitialized) passphraseField.text?.clear()
        gatewayPasswordField?.text?.clear()
        gatewayPassphraseField?.text?.clear()
    }

    private fun disposeBrowser() {
        popups.toList().forEach(::disposePopup)
        browser?.apply {
            stopLoading()
            (parent as? ViewGroup)?.removeView(this)
            destroy()
        }
        browser = null
    }

    private fun disposePopup(view: WebView) {
        if (popups.remove(view)) {
            view.stopLoading()
            view.destroy()
        }
    }

    override fun onStart() {
        super.onStart()
        visible = true
        initialHandoff?.let { handoff ->
            initialHandoff = null
            openPanel(handoff)
        }
    }

    override fun onStop() {
        visible = false
        initialHandoff?.clear()
        initialHandoff = null
        activeHandoff?.clear()
        activeHandoff = null
        nativeGrantEligible = false
        nativeGrantRequest++
        bootstrapRequest++
        bootstrapDialog?.dismiss()
        clearCopiedPassword(forceIfUnreadable = true)
        bootstrapButton?.isEnabled = false
        panelRetryButton?.isEnabled = false
        if (tunnel != null || opening) {
            val opened = tunnel
            tunnel = null
            activeTunnelPort = null
            opened?.close()
            if (profilePickerActive) disposeBrowser()
            if (!profilePickerActive && !profileSaveInProgress) finish()
        }
        super.onStop()
    }

    override fun onDestroy() {
        disposed = true
        nativeGrantEligible = false
        nativeGrantRequest++
        bootstrapRequest++
        bootstrapDialog?.dismiss()
        clearCopiedPassword(forceIfUnreadable = true)
        bootstrapButton = null
        nativeGrantButton = null
        panelRetryButton = null
        pendingProfile?.bytes?.fill(0)
        pendingProfile = null
        clearSecretFields()
        initialHandoff?.clear()
        initialHandoff = null
        activeHandoff?.clear()
        activeHandoff = null
        selectedKeyUri = null
        selectedGatewayKeyUri = null
        disposeBrowser()
        val opened = tunnel
        tunnel = null
        activeTunnelPort = null
        opened?.close()
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_PRIVATE_KEY = 71
        private const val REQUEST_SAVE_PROFILE = 72
        private const val REQUEST_GATEWAY_PRIVATE_KEY = 73
        private const val MAX_PROFILE_MESSAGE_LENGTH = 24 * 1024
    }
}
