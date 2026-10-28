/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.WindowManager
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import kotlin.math.roundToInt

/** Direct HTTPS access to a SovaGrid Hub; no credentials or session token are saved on disk. */
class HubActivity : Activity() {
    private enum class Tab { SERVERS, CHECKS, FILESYSTEMS, SERVICES, CONTAINERS, INCIDENTS }
    private val worker = Executors.newSingleThreadExecutor()
    private val serviceWorker = Executors.newSingleThreadExecutor()
    private val containerWorker = Executors.newSingleThreadExecutor()
    private val filesystemWorker = Executors.newSingleThreadExecutor()
    private var api: HubApi? = null
    private var session: HubSession? = null
    private var selectedTab = Tab.SERVERS
    private var selectedCheckServerId: String? = null
    private var checkSummary: HubChecksSummary? = null
    private var checksError: String? = null
    private var selectedServiceServerId: String? = null
    private var serviceUnitDraft = "nginx.service"
    private var serviceControl: HubServiceControl? = null
    private var serviceControlElapsed = 0L
    private var serviceMessage = "Проверьте состояние службы перед действием."
    private var serviceBusy = false
    @Volatile private var serviceOperationId = 0
    private var selectedContainerServerId: String? = null
    private var selectedContainerId: String? = null
    private var containerControl: HubContainerControl? = null
    private var containerControlElapsed = 0L
    private var containerMessage = "Выберите контейнер и проверьте его состояние."
    private var containerBusy = false
    @Volatile private var containerOperationId = 0
    private var selectedFilesystemServerId: String? = null
    private var filesystemState: HubFilesystemAlertsState? = null
    private var filesystemMessage = "Выберите сервер для просмотра дисковых тревог."
    private var filesystemBusy = false
    @Volatile private var filesystemOperationId = 0
    @Volatile private var requestGeneration = 0
    @Volatile private var disposed = false
    private var addressDraft = ""
    private var usernameDraft = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        AppTheme.apply(this)
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        showLogin()
    }

    private fun Int.dp() = (this * resources.displayMetrics.density).roundToInt()

    private fun column() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(16.dp(), 16.dp(), 16.dp(), 16.dp())
    }

    private fun label(value: String, size: Float = 16f) = TextView(this).apply {
        text = value
        textSize = size
        setPadding(0, 6.dp(), 0, 6.dp())
    }

    private fun showLogin(notice: String? = null) {
        val root = column()
        root.addView(label("SovaGrid Hub", 26f))
        root.addView(label("Вход в мониторинг по HTTPS"))
        val address = EditText(this).apply {
            hint = "https://hub.example.com"
            setText(addressDraft)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
        }
        val username = EditText(this).apply {
            hint = "Логин Hub"
            setText(usernameDraft)
            isSingleLine = true
        }
        val password = EditText(this).apply {
            hint = "Пароль Hub"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            isSingleLine = true
        }
        root.addView(address)
        root.addView(username)
        root.addView(password)
        val status = label(notice ?: "Пароль и токен хранятся только во время работы приложения.", 14f)
        val login = Button(this).apply { text = "Войти" }
        login.setOnClickListener {
            val candidate = try {
                HubApi(address.text.toString())
            } catch (error: IllegalArgumentException) {
                address.error = error.message
                return@setOnClickListener
            }
            addressDraft = address.text.toString().trim()
            usernameDraft = username.text.toString().trim()
            if (usernameDraft.isBlank() || password.text.isEmpty()) {
                status.text = "Введите логин и пароль."
                return@setOnClickListener
            }
            val secret = CharArray(password.text.length) { password.text[it] }
            val account = usernameDraft
            password.text.clear()
            login.isEnabled = false
            status.text = "Вход и загрузка мониторинга…"
            val generation = ++requestGeneration
            worker.execute {
                var acquiredToken: String? = null
                try {
                    if (disposed || generation != requestGeneration) return@execute
                    val acquiredSession = candidate.login(account, secret)
                    acquiredToken = acquiredSession.token
                    val latest = candidate.snapshot(acquiredSession)
                    postUi {
                        if (generation != requestGeneration) {
                            worker.execute { runCatching { candidate.logout(acquiredSession.token) } }
                            return@postUi
                        }
                        api = candidate
                        session = acquiredSession
                        selectedTab = Tab.SERVERS
                        selectedCheckServerId = null
                        checkSummary = null
                        checksError = null
                        selectedServiceServerId = latest.servers.firstOrNull {
                            acquiredSession.canAdminister(it.id)
                        }?.id ?: latest.servers.firstOrNull()?.id
                        serviceControl = null
                        serviceBusy = false
                        selectedContainerServerId = latest.servers.firstOrNull {
                            acquiredSession.canAdminister(it.id)
                        }?.id ?: latest.servers.firstOrNull()?.id
                        selectedContainerId = null
                        containerControl = null
                        containerBusy = false
                        selectedFilesystemServerId = latest.servers.firstOrNull()?.id
                        filesystemState = null
                        filesystemBusy = false
                        filesystemMessage = "Откройте вкладку «Диски» для загрузки правил."
                        showDashboard(latest)
                    }
                } catch (error: Exception) {
                    acquiredToken?.let { runCatching { candidate.logout(it) } }
                    postUi {
                        if (generation != requestGeneration) return@postUi
                        status.text = when (error) {
                            is HubIdentityException -> "Hub не подтвердил учётную запись и её права. Обновите Hub или обратитесь к администратору."
                            is HubHttpException -> when (error.statusCode) {
                                401, 403 -> "Неверный логин или пароль, либо доступ запрещён."
                                else -> "Hub ответил кодом ${error.statusCode}."
                            }
                            else -> "Не удалось подключиться к Hub. Проверьте HTTPS-адрес и сеть."
                        }
                        login.isEnabled = true
                    }
                } finally {
                    secret.fill('\u0000')
                }
            }
        }
        root.addView(login)
        root.addView(status)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun showDashboard(latest: HubSnapshot) {
        val root = column()
        root.addView(label("SovaGrid Hub", 26f))
        root.addView(label(addressDraft, 14f))
        val identity = session?.identity
        if (identity == null) {
            returnToLogin("Войдите в Hub снова.")
            return
        }
        root.addView(label("${identity.username} · ${identity.role.label}", 15f))
        root.addView(label("Время показано для ${java.time.ZoneId.systemDefault().id} (часовой пояс телефона). Серверные отметки хранятся в секундах Unix (UTC).", 13f))
        if (identity.role == HubRole.VIEWER) root.addView(label(
            "Просмотр мониторинга и событий. Подтверждать тревоги может оператор или администратор сервера.", 13f
        ))
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val activeCount = latest.incidents.count { it.state == "firing" }
        val status = label("Серверов: ${latest.servers.size} · активных тревог: $activeCount", 14f)
        val refresh = Button(this).apply { text = "Обновить" }
        refresh.setOnClickListener {
            val currentApi = api ?: return@setOnClickListener
            val currentSession = session ?: return@setOnClickListener
            val generation = ++requestGeneration
            refresh.isEnabled = false
            status.text = "Обновляем мониторинг…"
            worker.execute {
                try {
                    if (disposed || generation != requestGeneration) return@execute
                    val refreshed = currentApi.snapshot(currentSession)
                    postUi {
                        if (generation == requestGeneration) {
                            checkSummary = null
                            checksError = null
                            serviceControl = null
                            serviceMessage = "Данные обновлены. Проверьте службу снова."
                            containerControl = null
                            containerMessage = "Данные обновлены. Проверьте контейнер снова."
                            filesystemOperationId++
                            filesystemState = null
                            filesystemBusy = false
                            filesystemMessage = "Загружаем правила дисковых тревог…"
                            selectedFilesystemServerId = selectedFilesystemServerId?.takeIf { id ->
                                refreshed.servers.any { it.id == id }
                            } ?: refreshed.servers.firstOrNull()?.id
                            selectedCheckServerId = selectedCheckServerId?.takeIf { id -> refreshed.servers.any { it.id == id } }
                                ?: refreshed.servers.firstOrNull()?.id
                            showDashboard(refreshed)
                            if (selectedTab == Tab.CHECKS) selectedCheckServerId?.let { loadChecks(refreshed, it) }
                            if (selectedTab == Tab.FILESYSTEMS) selectedFilesystemServerId?.let { loadFilesystemAlerts(refreshed, it) }
                        }
                    }
                } catch (error: Exception) {
                    postUi {
                        if (generation != requestGeneration) return@postUi
                        if (isAccessFailure(error)) {
                            returnToLogin("Сеанс завершён или права доступа изменились. Войдите снова.")
                            return@postUi
                        }
                        status.text = when (error) {
                            is HubHttpException -> "Ошибка Hub: HTTP ${error.statusCode}."
                            else -> "Не удалось обновить данные."
                        }
                        refresh.isEnabled = true
                    }
                }
            }
        }
        val logout = Button(this).apply {
            text = "Выйти"
            setOnClickListener {
                val currentApi = api
                val currentSession = session
                requestGeneration++
                session = null
                api = null
                selectedTab = Tab.SERVERS
                selectedCheckServerId = null
                checkSummary = null
                checksError = null
                serviceOperationId++
                selectedServiceServerId = null
                serviceControl = null
                serviceBusy = false
                containerOperationId++
                selectedContainerServerId = null
                selectedContainerId = null
                containerControl = null
                containerBusy = false
                filesystemOperationId++
                selectedFilesystemServerId = null
                filesystemState = null
                filesystemBusy = false
                showLogin()
                if (currentApi != null && currentSession != null) {
                    worker.execute { runCatching { currentApi.logout(currentSession.token) } }
                }
            }
        }
        actions.addView(refresh, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(logout)
        root.addView(actions)
        root.addView(status)
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val serversTab = Button(this).apply {
            text = if (selectedTab == Tab.SERVERS) "● Серверы" else "Серверы"
            isAllCaps = false
            setOnClickListener { selectedTab = Tab.SERVERS; showDashboard(latest) }
        }
        val incidentsTab = Button(this).apply {
            text = if (selectedTab == Tab.INCIDENTS) "● События ($activeCount)" else "События ($activeCount)"
            isAllCaps = false
            setOnClickListener { selectedTab = Tab.INCIDENTS; showDashboard(latest) }
        }
        val checksTab = Button(this).apply {
            text = if (selectedTab == Tab.CHECKS) "● Проверки" else "Проверки"
            isAllCaps = false
            setOnClickListener { openChecks(latest, selectedCheckServerId ?: latest.servers.firstOrNull()?.id) }
        }
        val servicesTab = Button(this).apply {
            text = if (selectedTab == Tab.SERVICES) "● Службы" else "Службы"
            isAllCaps = false
            setOnClickListener { selectedTab = Tab.SERVICES; showDashboard(latest) }
        }
        val containersTab = Button(this).apply {
            text = if (selectedTab == Tab.CONTAINERS) "● Контейнеры" else "Контейнеры"
            isAllCaps = false
            setOnClickListener { selectedTab = Tab.CONTAINERS; showDashboard(latest) }
        }
        val filesystemsTab = Button(this).apply {
            text = if (selectedTab == Tab.FILESYSTEMS) "● Диски" else "Диски"
            isAllCaps = false
            setOnClickListener { openFilesystemAlerts(latest, selectedFilesystemServerId ?: latest.servers.firstOrNull()?.id) }
        }
        tabs.addView(serversTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        tabs.addView(checksTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        tabs.addView(servicesTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(tabs)
        val secondTabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        secondTabs.addView(filesystemsTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secondTabs.addView(containersTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secondTabs.addView(incidentsTab, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(secondTabs)
        when (selectedTab) {
            Tab.SERVERS -> renderServers(root, latest.servers)
            Tab.CHECKS -> renderChecks(root, latest)
            Tab.FILESYSTEMS -> renderFilesystemAlerts(root, latest)
            Tab.SERVICES -> renderServices(root, latest)
            Tab.CONTAINERS -> renderContainers(root, latest)
            Tab.INCIDENTS -> renderIncidents(root, latest.incidents, status)
        }
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun renderServers(root: LinearLayout, servers: List<HubServer>) {
        if (servers.isEmpty()) root.addView(label("На Hub пока нет серверов."))
        servers.forEach { server ->
            val state = if (server.online) "● В сети" else "○ Нет связи"
            root.addView(label("${server.name} · $state", 19f))
            session?.effectiveRole(server.id)?.let { root.addView(label("Доступ: ${it.label}", 13f)) }
            root.addView(label(
                "CPU ${percent(server.cpuPercent)}  ·  RAM ${percent(server.memoryPercent)}  ·  Диск ${percent(server.diskPercent)}"
            ))
            val stamp = server.collectedAt ?: server.lastSeen
            if (stamp != null) root.addView(label("Последние данные: ${HubMonitoring.localStamp(stamp)}", 13f))
            if (server.uptimeSeconds != null) root.addView(label("Uptime: ${server.uptimeSeconds / 3600} ч", 13f))
            server.clock?.let { clock ->
                root.addView(label("Часы сервера при сборе данных (в зоне телефона): ${HubMonitoring.localStamp(clock.systemUtcEpoch)}", 13f))
                clock.timezone?.let { root.addView(label("Часовой пояс сервера: $it", 13f)) }
                root.addView(label("NTP: ${when (clock.ntpSynchronized) {
                    true -> "синхронизация подтверждена"
                    false -> "нет подтверждения синхронизации"
                    null -> "нет данных"
                }}", 13f))
                root.addView(label(HubMonitoring.rtcOffset(clock), 13f))
            }
        }
    }

    private fun openChecks(latest: HubSnapshot, serverId: String?) {
        selectedTab = Tab.CHECKS
        selectedCheckServerId = serverId?.takeIf { id -> latest.servers.any { it.id == id } }
        checkSummary = null
        checksError = if (selectedCheckServerId == null) null else "Загружаем проверки…"
        showDashboard(latest)
        selectedCheckServerId?.let { loadChecks(latest, it) }
    }

    private fun loadChecks(latest: HubSnapshot, serverId: String) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        val generation = ++requestGeneration
        worker.execute {
            try {
                if (disposed || generation != requestGeneration) return@execute
                val summary = currentApi.checks(currentSession, serverId)
                postUi {
                    if (generation != requestGeneration || selectedCheckServerId != serverId) return@postUi
                    checkSummary = summary
                    checksError = null
                    showDashboard(latest)
                }
            } catch (error: Exception) {
                postUi {
                    if (generation != requestGeneration || selectedCheckServerId != serverId) return@postUi
                    if (isAccessFailure(error)) {
                        returnToLogin("Сеанс завершён или права доступа изменились. Войдите снова.")
                        return@postUi
                    }
                    checksError = when (error) {
                        is HubHttpException -> if (error.statusCode == 404) "Hub пока не поддерживает проверки доступности."
                            else "Не удалось загрузить проверки: HTTP ${error.statusCode}."
                        else -> "Не удалось загрузить проверки. Проверьте сеть и обновите экран."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun renderChecks(root: LinearLayout, latest: HubSnapshot) {
        root.addView(label("Проверки доступности", 20f))
        root.addView(label("HTTP/HTTPS, TCP и DNS. Адреса целей доступны администратору в полной панели Hub.", 13f))
        if (latest.servers.isEmpty()) {
            root.addView(label("На Hub пока нет серверов."))
            return
        }
        root.addView(label("Сервер", 13f))
        root.addView(Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item,
                latest.servers.map { it.name })
            setSelection(latest.servers.indexOfFirst { it.id == selectedCheckServerId }.coerceAtLeast(0), false)
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val selected = latest.servers[position].id
                    if (selected != selectedCheckServerId) openChecks(latest, selected)
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        })
        val summary = checkSummary?.takeIf { it.serverId == selectedCheckServerId }
        if (summary == null) {
            root.addView(label(checksError ?: "Выберите сервер для просмотра проверок."))
            return
        }
        root.addView(label("Агент получал задания: ${HubMonitoring.localStamp(summary.workerSeenAt)}", 13f))
        if (summary.checks.isEmpty()) root.addView(label("Для сервера проверки ещё не настроены."))
        for (check in summary.checks) {
            val kind = HubMonitoring.checkKind(check.kind)
            root.addView(label("${check.name} · $kind · ${HubMonitoring.checkState(check.state)}", 17f))
            root.addView(label("Интервал ${check.intervalSeconds} с · таймаут ${check.timeoutSeconds} с", 13f))
            check.latest?.let { result ->
                val qualifier = if (check.state in setOf("stale", "disabled")) "Последний, возможно устаревший результат" else "Последний результат"
                root.addView(label("$qualifier: ${if (result.status == "up") "доступна" else "недоступна"} · ${HubMonitoring.localStamp(result.observedAt)}", 13f))
                root.addView(label("Получен Hub: ${HubMonitoring.localStamp(result.receivedAt)} · задержка ${result.latencyMs} мс", 13f))
                result.httpStatus?.let { root.addView(label("HTTP: $it", 13f)) }
                result.tlsExpiresAt?.let { root.addView(label("Срок сертификата TLS: ${HubMonitoring.localStamp(it)}", 13f)) }
                if (result.errorCode != null) root.addView(label(HubMonitoring.checkError(result.errorCode), 13f))
            }
        }
    }

    private fun openFilesystemAlerts(latest: HubSnapshot, serverId: String?) {
        selectedTab = Tab.FILESYSTEMS
        selectedFilesystemServerId = serverId?.takeIf { id -> latest.servers.any { it.id == id } }
        filesystemState = null
        filesystemMessage = if (selectedFilesystemServerId == null) "На Hub пока нет серверов." else "Загружаем правила дисковых тревог…"
        showDashboard(latest)
        selectedFilesystemServerId?.let { loadFilesystemAlerts(latest, it) }
    }

    private fun loadFilesystemAlerts(latest: HubSnapshot, serverId: String) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        val operation = ++filesystemOperationId
        filesystemBusy = true
        filesystemMessage = "Загружаем правила дисковых тревог…"
        showDashboard(latest)
        filesystemWorker.execute {
            try {
                val loaded = currentApi.filesystemAlerts(currentSession, serverId)
                postUi {
                    if (operation != filesystemOperationId || session !== currentSession ||
                        selectedFilesystemServerId != serverId) return@postUi
                    filesystemState = loaded
                    filesystemBusy = false
                    filesystemMessage = "Правила обновлены."
                    showDashboard(latest)
                }
            } catch (error: Exception) {
                postUi {
                    if (operation != filesystemOperationId || session !== currentSession ||
                        selectedFilesystemServerId != serverId) return@postUi
                    if (isAccessFailure(error)) {
                        returnToLogin("Сеанс завершён или права изменились. Войдите снова.")
                        return@postUi
                    }
                    filesystemState = null
                    filesystemBusy = false
                    filesystemMessage = if (error is HubHttpException && error.statusCode == 404)
                        "Обновите Hub для дисковых тревог." else "Не удалось загрузить правила. Проверьте сеть и обновите экран."
                    showDashboard(latest)
                }
            }
        }
    }

    private fun renderFilesystemAlerts(root: LinearLayout, latest: HubSnapshot) {
        root.addView(label("Тревоги по дискам и inode", 20f))
        root.addView(label("Правила работают на выбранном Ubuntu-сервере. Неполный или устаревший снимок не закрывает тревогу.", 13f))
        if (latest.servers.isEmpty()) {
            root.addView(label("На Hub пока нет серверов."))
            return
        }
        val currentSession = session ?: return
        val selected = latest.servers.firstOrNull { it.id == selectedFilesystemServerId }
            ?: latest.servers.first().also { selectedFilesystemServerId = it.id }
        root.addView(label("Сервер", 13f))
        root.addView(Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item,
                latest.servers.map { it.name + if (it.online) "" else " · нет связи" })
            setSelection(latest.servers.indexOfFirst { it.id == selected.id }, false)
            isEnabled = !filesystemBusy
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val chosen = latest.servers[position].id
                    if (chosen != selectedFilesystemServerId) openFilesystemAlerts(latest, chosen)
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        })
        root.addView(label("Доступ: ${currentSession.effectiveRole(selected.id)?.label ?: "нет"}", 13f))
        root.addView(label(filesystemMessage, 14f))
        root.addView(Button(this).apply {
            text = "Обновить правила"
            isAllCaps = false
            isEnabled = !filesystemBusy
            setOnClickListener { loadFilesystemAlerts(latest, selected.id) }
        })
        val data = filesystemState?.takeIf { it.serverId == selected.id } ?: return
        val source = when (data.sourceStatus) {
            "ok" -> "свежий полный список"
            "partial" -> "неполный список"
            "stale" -> "данные устарели"
            else -> "данные недоступны"
        }
        root.addView(label("Источник: $source · ${HubMonitoring.localStamp(data.observedAt)}", 13f))
        root.addView(label("Подтверждение тревоги: ${if (data.holdSeconds == 0) "сразу" else "${data.holdSeconds} с"}", 13f))
        if (data.filesystems.isNotEmpty()) {
            root.addView(label("Сейчас на файловых системах", 17f))
            for (mount in data.filesystems) {
                root.addView(label("${mount.mountpoint} · ${mount.fstype}", 15f))
                root.addView(label("Место ${percent(mount.spaceUsedPercent)} · inode ${percent(mount.inodesUsedPercent)}", 13f))
            }
        }
        val admin = currentSession.canAdminister(selected.id)
        if (admin) {
            root.addView(Button(this).apply {
                text = "Время подтверждения"
                isAllCaps = false
                isEnabled = !filesystemBusy
                setOnClickListener { editFilesystemHold(latest, selected, data) }
            })
            val configured = data.rules.map { it.mountpoint to it.metric }.toSet()
            if (HubFilesystemAlerts.available(data, selected).any { it !in configured } && data.rules.size < 32) {
                root.addView(Button(this).apply {
                    text = "Добавить правило"
                    isAllCaps = false
                    isEnabled = !filesystemBusy
                    setOnClickListener { editFilesystemRule(latest, selected, data, null) }
                })
            }
        }
        if (data.rules.isEmpty()) root.addView(label("Правил пока нет. Администратор может выбрать диск из свежего списка Agent."))
        for (rule in data.rules) {
            val observation = data.observations.firstOrNull { it.mountpoint == rule.mountpoint && it.metric == rule.metric }
            val metricLabel = if (rule.metric == "space") "Место" else "Inode"
            val status = when (observation?.status) {
                "alert" -> "порог достигнут"
                "normal" -> "норма"
                else -> "нет достоверных данных"
            }
            root.addView(label(rule.mountpoint, 17f))
            root.addView(label("$metricLabel · порог ${rule.thresholdPercent}% · $status" +
                (observation?.usedPercent?.let { " · занято ${formatValue("%.1f", it)}%" } ?: ""), 13f))
            if (admin) {
                val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                actions.addView(Button(this).apply {
                    text = "Изменить"
                    isAllCaps = false
                    isEnabled = !filesystemBusy
                    setOnClickListener { editFilesystemRule(latest, selected, data, rule) }
                }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                actions.addView(Button(this).apply {
                    text = "Удалить"
                    isAllCaps = false
                    isEnabled = !filesystemBusy
                    setOnClickListener {
                        confirmFilesystemChange(latest, selected, data,
                            data.rules.filterNot { it.mountpoint == rule.mountpoint && it.metric == rule.metric },
                            data.holdSeconds, "Удалить правило для ${rule.mountpoint} · $metricLabel?")
                    }
                }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                root.addView(actions)
            }
        }
    }

    private fun editFilesystemRule(latest: HubSnapshot, server: HubServer,
                                   state: HubFilesystemAlertsState, existing: HubFilesystemRule?) {
        val currentSession = session ?: return
        if (!currentSession.canAdminister(server.id) || filesystemBusy || filesystemState !== state) return
        val configured = state.rules.map { it.mountpoint to it.metric }.toSet()
        val options = if (existing != null) listOf(existing.mountpoint to existing.metric) else
            HubFilesystemAlerts.available(state, server).filter { it !in configured }
        if (options.isEmpty()) return
        val form = column()
        val choices = options.map { (path, metric) -> "$path · ${if (metric == "space") "место" else "inode"}" }
        val spinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item, choices)
            isEnabled = existing == null
        }
        form.addView(label("Файловая система и показатель", 13f))
        form.addView(spinner)
        val threshold = EditText(this).apply {
            hint = "Порог занятости, % (1–100)"
            inputType = InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
            setText((existing?.thresholdPercent ?: 90).toString())
        }
        form.addView(threshold)
        val dialog = AlertDialog.Builder(this).setTitle(if (existing == null) "Добавить тревогу" else "Изменить порог")
            .setView(form).setNegativeButton("Отмена", null).setPositiveButton("Продолжить", null).create()
        dialog.show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val value = threshold.text.toString().toIntOrNull()
            if (value == null || value !in 1..100) {
                threshold.error = "Укажите целое число от 1 до 100"
                return@setOnClickListener
            }
            val (path, metric) = options[spinner.selectedItemPosition.coerceIn(options.indices)]
            val next = state.rules.filterNot { it.mountpoint == path && it.metric == metric } +
                HubFilesystemRule(path, metric, value)
            dialog.dismiss()
            confirmFilesystemChange(latest, server, state, next, state.holdSeconds,
                "Сохранить порог $value% для $path · ${if (metric == "space") "место" else "inode"}?")
        }
    }

    private fun editFilesystemHold(latest: HubSnapshot, server: HubServer, state: HubFilesystemAlertsState) {
        if (session?.canAdminister(server.id) != true || filesystemBusy || filesystemState !== state) return
        val field = EditText(this).apply {
            hint = "От 0 до 86400 секунд"
            inputType = InputType.TYPE_CLASS_NUMBER
            isSingleLine = true
            setText(state.holdSeconds.toString())
        }
        val dialog = AlertDialog.Builder(this).setTitle("Время подтверждения тревоги")
            .setMessage("0 означает сразу. Правило применяется ко всем дискам выбранного сервера.")
            .setView(field).setNegativeButton("Отмена", null).setPositiveButton("Продолжить", null).create()
        dialog.show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val seconds = field.text.toString().toIntOrNull()
            if (seconds == null || seconds !in 0..86400) {
                field.error = "Укажите целое число от 0 до 86400"
                return@setOnClickListener
            }
            dialog.dismiss()
            confirmFilesystemChange(latest, server, state, state.rules, seconds,
                "Сохранить задержку $seconds с для ${server.name}?")
        }
    }

    private fun confirmFilesystemChange(latest: HubSnapshot, server: HubServer,
                                        state: HubFilesystemAlertsState, rules: List<HubFilesystemRule>,
                                        holdSeconds: Int, summary: String) {
        if (session?.canAdminister(server.id) != true || filesystemBusy || filesystemState !== state ||
            !HubFilesystemAlerts.validProposal(rules, holdSeconds)) return
        AlertDialog.Builder(this).setTitle("Изменить дисковые тревоги?")
            .setMessage("${server.name}: $summary Изменение будет применено к серверу через Hub.")
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Сохранить") { _, _ -> saveFilesystemAlerts(latest, server, state, rules, holdSeconds) }
            .show()
    }

    private fun saveFilesystemAlerts(latest: HubSnapshot, server: HubServer,
                                     before: HubFilesystemAlertsState, rules: List<HubFilesystemRule>,
                                     holdSeconds: Int) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        if (!currentSession.canAdminister(server.id) || filesystemBusy || filesystemState !== before ||
            selectedFilesystemServerId != server.id || !HubFilesystemAlerts.validProposal(rules, holdSeconds)) return
        val operation = ++filesystemOperationId
        filesystemBusy = true
        filesystemMessage = "Сохраняем правила…"
        showDashboard(latest)
        filesystemWorker.execute {
            try {
                if (disposed || operation != filesystemOperationId) return@execute
                val saved = currentApi.saveFilesystemAlerts(currentSession, before, rules, holdSeconds)
                postUi {
                    if (operation != filesystemOperationId || session !== currentSession ||
                        selectedFilesystemServerId != server.id) return@postUi
                    filesystemState = saved
                    filesystemBusy = false
                    filesystemMessage = "Правила сохранены. Ожидаем новый снимок Agent."
                    showDashboard(latest)
                }
            } catch (error: Exception) {
                val readback = if (isAccessFailure(error)) null else
                    runCatching { currentApi.filesystemAlerts(currentSession, server.id) }.getOrNull()
                postUi {
                    if (operation != filesystemOperationId || session !== currentSession ||
                        selectedFilesystemServerId != server.id) return@postUi
                    if (isAccessFailure(error)) {
                        returnToLogin("Сеанс завершён или права изменились. Проверьте тревоги после входа.")
                        return@postUi
                    }
                    filesystemState = readback
                    filesystemBusy = false
                    filesystemMessage = when {
                        readback != null && readback.revision == before.revision + 1 &&
                            readback.rules == rules && readback.holdSeconds == holdSeconds ->
                            "Изменение подтверждено повторным чтением Hub."
                        error is HubHttpException && error.statusCode == 409 ->
                            "Правила уже изменились. Прочитайте их и начните изменение заново."
                        readback == null ->
                            "Результат сохранения неизвестен. Повторное чтение не удалось; обновите правила перед новым действием."
                        else -> "Результат сохранения неизвестен. Правила прочитаны заново; проверьте их перед новым действием."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun renderServices(root: LinearLayout, latest: HubSnapshot) {
        root.addView(label("Системные службы", 20f))
        root.addView(label("Выберите сервер и введите точное имя службы, например nginx.service. " +
            "Действия доступны только администратору и отдельно разрешаются на самом сервере.", 13f))
        if (latest.servers.isEmpty()) {
            root.addView(label("На Hub пока нет серверов."))
            return
        }
        val currentSession = session ?: return
        val selected = latest.servers.firstOrNull { it.id == selectedServiceServerId }
            ?: latest.servers.first().also { selectedServiceServerId = it.id }
        root.addView(label("Сервер", 13f))
        root.addView(Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item,
                latest.servers.map { it.name + if (it.online) "" else " · нет связи" })
            setSelection(latest.servers.indexOfFirst { it.id == selected.id }, false)
            isEnabled = !serviceBusy
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val serverId = latest.servers[position].id
                    if (serverId != selectedServiceServerId) {
                        selectedServiceServerId = serverId
                        serviceControl = null
                        serviceMessage = "Сервер изменён. Проверьте службу заново."
                        showDashboard(latest)
                    }
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        })
        root.addView(label("Доступ: ${currentSession.effectiveRole(selected.id)?.label ?: "нет"} · " +
            if (selected.remoteCommandsEnabled) "задания включены" else "задания выключены", 13f))
        val name = EditText(this).apply {
            hint = "nginx.service"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            isSingleLine = true
            setText(serviceUnitDraft)
            isEnabled = !serviceBusy
        }
        root.addView(name)
        val status = label(serviceMessage, 14f)
        root.addView(status)
        val policy = label("", 13f)
        root.addView(policy)
        val details = label("", 13f)
        root.addView(details)
        val check = Button(this).apply {
            text = if (serviceBusy) "Ожидаем Hub…" else "Проверить состояние"
            isAllCaps = false
            setOnClickListener {
                val unit = name.text.toString().trim()
                if (!HubServices.validUnit(unit)) {
                    name.error = "Укажите точное имя вида nginx.service"
                } else checkService(latest, selected, unit)
            }
        }
        root.addView(check)
        val mutationButtons = HubServiceAction.entries.filter { it != HubServiceAction.STATUS }.map { action ->
            Button(this).apply {
                text = action.label
                isAllCaps = false
                setOnClickListener { confirmServiceAction(latest, selected, action, name.text.toString().trim()) }
                root.addView(this)
            }
        }
        fun updateActions() {
            val unit = name.text.toString().trim()
            val age = SystemClock.elapsedRealtime() - serviceControlElapsed
            val fresh = HubServices.canMutate(selected, currentSession, unit, serviceControl, age) && !serviceBusy
            check.isEnabled = HubServices.canCheck(selected, currentSession) && HubServices.validUnit(unit) && !serviceBusy
            mutationButtons.forEach { it.isEnabled = fresh }
            policy.text = when {
                HubServices.protectedUnit(unit) -> "Эту службу можно только проверять: доступ, сеть и VPN защищены."
                !HubServices.canCheck(selected, currentSession) -> "Нужны права администратора, работающий Agent и разрешённые команды."
                serviceControl?.sourceStatus == "ok" && age !in 0 until 85_000 -> "Проверка устарела. Обновите состояние."
                else -> "После любого действия запросите состояние снова. При тайм-ауте результат может быть неопределённым."
            }
            details.text = serviceControl?.takeIf { it.unit == unit && it.sourceStatus == "ok" }?.let { control ->
                "Последняя проверка: ${HubMonitoring.localStamp(control.observedAt)} · " +
                    "${control.loadState} / ${control.activeState} / ${control.subState}"
            } ?: ""
        }
        name.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                val changed = s.toString().trim()
                if (changed != serviceUnitDraft) {
                    serviceUnitDraft = changed
                    serviceControl = null
                    serviceMessage = "Имя изменено. Проверьте состояние заново."
                    status.text = serviceMessage
                }
                updateActions()
            }
        })
        updateActions()
    }

    private fun checkService(latest: HubSnapshot, server: HubServer, unit: String) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        if (!HubServices.canCheck(server, currentSession)) {
            serviceMessage = "Для проверки нужны права администратора и подключённый Agent."
            showDashboard(latest)
            return
        }
        val operation = ++serviceOperationId
        serviceUnitDraft = unit
        serviceControl = null
        serviceBusy = true
        serviceMessage = "Запрашиваем состояние $unit…"
        showDashboard(latest)
        serviceWorker.execute {
            try {
                val refreshed = currentApi.snapshot(currentSession)
                val actual = refreshed.servers.firstOrNull { it.id == server.id }
                    ?: throw HubIdentityException()
                if (!HubServices.canCheck(actual, currentSession)) throw HubIdentityException()
                val job = currentApi.queueServiceAction(currentSession, actual, HubServiceAction.STATUS,
                    unit, UUID.randomUUID().toString())
                val finished = awaitServiceJob(currentApi, currentSession, actual.id, job.id, operation)
                val control = if (finished.state == "succeeded")
                    currentApi.serviceControl(currentSession, actual.id, unit) else null
                postUi {
                    if (operation != serviceOperationId || session !== currentSession) return@postUi
                    serviceBusy = false
                    serviceControl = control?.takeIf { it.sourceStatus == "ok" }
                    serviceControlElapsed = if (serviceControl != null) SystemClock.elapsedRealtime() else 0L
                    serviceMessage = if (serviceControl != null) "Состояние подтверждено."
                        else "Состояние не подтвердилось. Проверьте Agent и разрешения службы."
                    showDashboard(refreshed)
                }
            } catch (error: Exception) {
                postUi {
                    if (operation != serviceOperationId || session !== currentSession) return@postUi
                    serviceBusy = false
                    serviceControl = null
                    if (error is HubHttpException && error.statusCode == 401) {
                        returnToLogin("Сеанс завершён. Войдите снова.")
                        return@postUi
                    }
                    serviceMessage = when (error) {
                        is HubIdentityException -> "Права на сервер изменились. Обновите данные Hub."
                        is HubHttpException -> "Hub отклонил проверку: HTTP ${error.statusCode}."
                        else -> "Не удалось подтвердить состояние. Проверьте сеть и Agent."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun confirmServiceAction(latest: HubSnapshot, server: HubServer,
                                     action: HubServiceAction, unit: String) {
        val currentSession = session ?: return
        val proof = serviceControl
        val age = SystemClock.elapsedRealtime() - serviceControlElapsed
        if (!HubServices.canMutate(server, currentSession, unit, proof, age) || serviceBusy) {
            serviceMessage = "Состояние изменилось или проверка устарела. Проверьте службу заново."
            serviceControl = null
            showDashboard(latest)
            return
        }
        val confirmedProof = proof ?: return
        AlertDialog.Builder(this)
            .setTitle("${action.label} $unit?")
            .setMessage("Сервер: ${server.name}. Это изменит состояние systemd-службы. " +
                "После действия проверьте её состояние снова.")
            .setNegativeButton("Отмена", null)
            .setPositiveButton(action.label) { _, _ ->
                val activeSession = session ?: return@setPositiveButton
                if (activeSession !== currentSession || !HubServices.canMutate(
                        server, activeSession, unit, confirmedProof, SystemClock.elapsedRealtime() - serviceControlElapsed) ||
                    selectedServiceServerId != server.id || serviceUnitDraft != unit || serviceBusy) {
                    serviceControl = null
                    serviceMessage = "Состояние изменилось. Проверьте службу заново."
                    showDashboard(latest)
                    return@setPositiveButton
                }
                performServiceAction(latest, server, action, unit, confirmedProof)
            }.show()
    }

    private fun performServiceAction(latest: HubSnapshot, server: HubServer,
                                     action: HubServiceAction, unit: String, proof: HubServiceControl) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        val proofElapsed = serviceControlElapsed
        val operation = ++serviceOperationId
        serviceControl = null
        serviceBusy = true
        serviceMessage = "Отправляем действие ${action.label.lowercase(Locale.ROOT)}…"
        showDashboard(latest)
        serviceWorker.execute {
            var submitted = false
            var accepted = false
            try {
                val refreshed = currentApi.snapshot(currentSession)
                val actual = refreshed.servers.firstOrNull { it.id == server.id }
                    ?: throw HubIdentityException()
                val age = SystemClock.elapsedRealtime() - proofElapsed
                if (!HubServices.canMutate(actual, currentSession, unit, proof, age))
                    throw HubIdentityException()
                val current = currentApi.serviceControl(currentSession, server.id, unit)
                if (current != proof || current.sourceStatus != "ok") throw HubIdentityException()
                val key = UUID.randomUUID().toString()
                submitted = true
                val job = currentApi.queueServiceAction(currentSession, actual, action, unit, key,
                    proof, SystemClock.elapsedRealtime() - proofElapsed)
                accepted = true
                val finished = awaitServiceJob(currentApi, currentSession, server.id, job.id, operation)
                postUi {
                    if (operation != serviceOperationId || session !== currentSession) return@postUi
                    serviceBusy = false
                    serviceMessage = if (finished.state == "succeeded" && finished.exitCode == 0 &&
                        finished.result?.let { it.action == action && it.unit == unit && it.result == "ok" } == true)
                        "Действие выполнено. Проверьте состояние службы снова."
                        else "Исход действия не подтверждён. Проверьте состояние перед повтором."
                    showDashboard(refreshed)
                }
            } catch (error: Exception) {
                postUi {
                    if (operation != serviceOperationId || session !== currentSession) return@postUi
                    serviceBusy = false
                    if (error is HubHttpException && error.statusCode == 401) {
                        returnToLogin("Сеанс завершён. Проверьте состояние службы после входа.")
                        return@postUi
                    }
                    serviceMessage = when {
                        accepted && error is HubIdentityException ->
                            "Права изменились после отправки. Исход действия неизвестен; проверьте состояние."
                        error is HubIdentityException -> "Права или состояние сервера изменились. Проверьте службу заново."
                        submitted && !accepted && error is HubHttpException &&
                            error.statusCode in setOf(400, 403, 404, 409) ->
                            "Hub отклонил действие до очереди: HTTP ${error.statusCode}. Проверьте разрешения."
                        submitted -> "Исход действия неизвестен. Проверьте состояние перед повтором."
                        else -> "Действие не отправлено. Проверьте состояние заново."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun awaitServiceJob(api: HubApi, currentSession: HubSession, serverId: String,
                                jobId: String, operation: Int): HubServiceJob {
        val deadline = SystemClock.elapsedRealtime() + 75_000
        while (true) {
            if (disposed || operation != serviceOperationId || session !== currentSession)
                throw InterruptedException("Service view closed")
            val job = api.serviceJob(currentSession, serverId, jobId)
            if (job.terminal) return job
            if (SystemClock.elapsedRealtime() >= deadline) throw java.io.IOException("Service job timeout")
            Thread.sleep(1_000)
        }
    }

    private fun renderContainers(root: LinearLayout, latest: HubSnapshot) {
        root.addView(label("Docker-контейнеры", 20f))
        root.addView(label("Действия доступны администратору сервера для контейнеров из полного свежего инвентаря. " +
            "Защищённые компоненты показаны только для мониторинга.", 13f))
        if (latest.servers.isEmpty()) {
            root.addView(label("На Hub пока нет серверов."))
            return
        }
        val currentSession = session ?: return
        val selected = latest.servers.firstOrNull { it.id == selectedContainerServerId }
            ?: latest.servers.first().also { selectedContainerServerId = it.id }
        root.addView(label("Сервер", 13f))
        root.addView(Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item,
                latest.servers.map { it.name + if (it.online) "" else " · нет связи" })
            setSelection(latest.servers.indexOfFirst { it.id == selected.id }, false)
            isEnabled = !containerBusy
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val serverId = latest.servers[position].id
                    if (serverId != selectedContainerServerId) {
                        selectedContainerServerId = serverId
                        selectedContainerId = null
                        containerControl = null
                        containerMessage = "Сервер изменён. Проверьте контейнер заново."
                        showDashboard(latest)
                    }
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        })
        root.addView(label("Доступ: ${currentSession.effectiveRole(selected.id)?.label ?: "нет"} · " +
            if (selected.remoteCommandsEnabled) "задания включены" else "задания выключены", 13f))
        val source = selected.containers?.docker
        if (source == null) {
            root.addView(label("Agent ещё не прислал инвентарь контейнеров. Обновите мониторинг."))
            return
        }
        root.addView(label("Снимок: ${HubMonitoring.localStamp(selected.containers.collectedAt)} · " +
            when {
                source.sourceStatus != "ok" -> "Docker недоступен"
                source.truncated -> "неполный список; действия выключены"
                else -> "полный список"
            }, 13f))
        if (source.containers.isEmpty()) {
            root.addView(label("В инвентаре Docker нет контейнеров."))
            return
        }
        val container = source.containers.firstOrNull { it.id == selectedContainerId }
            ?: source.containers.first().also { selectedContainerId = it.id; containerControl = null }
        root.addView(label("Контейнер", 13f))
        root.addView(Spinner(this).apply {
            adapter = ArrayAdapter(this@HubActivity, android.R.layout.simple_spinner_dropdown_item,
                source.containers.map { it.name + " · " + it.id.take(12) +
                    if (HubContainers.protected(it)) " · защищён" else "" })
            setSelection(source.containers.indexOfFirst { it.id == container.id }, false)
            isEnabled = !containerBusy
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    val chosen = source.containers[position].id
                    if (chosen != selectedContainerId) {
                        selectedContainerId = chosen
                        containerControl = null
                        containerMessage = "Контейнер изменён. Проверьте состояние заново."
                        showDashboard(latest)
                    }
                }
                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
        })
        root.addView(label("${container.name} · ${container.image}", 16f))
        root.addView(label("ID: ${container.id}", 12f))
        root.addView(label("Инвентарь: ${container.state} · health ${container.health ?: "—"} · " +
            "CPU ${container.cpuPercent?.let(::percent) ?: "—"} · RAM ${container.memoryBytes?.let { "$it байт" } ?: "—"} · " +
            "перезапуски ${container.restarts ?: "—"}", 13f))
        val status = label(containerMessage, 14f)
        root.addView(status)
        val policy = label("", 13f)
        root.addView(policy)
        val details = label("", 13f)
        root.addView(details)
        val check = Button(this).apply {
            text = if (containerBusy) "Ожидаем Hub…" else "Проверить состояние"
            isAllCaps = false
            setOnClickListener { checkContainer(latest, selected, container) }
        }
        root.addView(check)
        val mutations = HubContainerAction.entries.filter { it != HubContainerAction.STATUS }.map { action ->
            Button(this).apply {
                text = action.label
                isAllCaps = false
                setOnClickListener { confirmContainerAction(latest, selected, container, action) }
                root.addView(this)
            }
        }
        val age = SystemClock.elapsedRealtime() - containerControlElapsed
        check.isEnabled = HubContainers.canCheck(selected, currentSession, container) && !containerBusy
        val canMutate = HubContainers.canMutate(selected, currentSession, container, containerControl, age) && !containerBusy
        mutations.forEach { it.isEnabled = canMutate; it.visibility = if (HubContainers.protected(container)) View.GONE else View.VISIBLE }
        policy.text = when {
            HubContainers.protected(container) -> "Защищённый контейнер: доступен только статус из инвентаря."
            !source.complete -> "Для действий нужен полный инвентарь Docker."
            !HubContainers.canCheck(selected, currentSession, container) ->
                "Нужны права администратора, работающий Agent и разрешённые команды."
            containerControl?.sourceStatus == "ok" && age !in 0 until 85_000 ->
                "Проверка устарела. Запросите состояние снова."
            else -> "После любого действия запросите состояние снова. Неизвестный исход нельзя повторять без проверки."
        }
        details.text = containerControl?.takeIf { it.id == container.id && it.sourceStatus == "ok" }?.let {
            "Последняя проверка: ${HubMonitoring.localStamp(it.observedAt)} · ${it.state}"
        } ?: ""
    }

    private fun checkContainer(latest: HubSnapshot, server: HubServer, container: HubContainer) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        if (!HubContainers.canCheck(server, currentSession, container) || containerBusy) return
        val operation = ++containerOperationId
        containerControl = null
        containerBusy = true
        containerMessage = "Запрашиваем состояние ${container.name}…"
        showDashboard(latest)
        containerWorker.execute {
            try {
                val refreshed = currentApi.snapshot(currentSession)
                val actual = refreshed.servers.firstOrNull { it.id == server.id } ?: throw HubIdentityException()
                val current = actual.containers?.docker?.containers?.firstOrNull { it.id == container.id }
                    ?: throw HubIdentityException()
                if (!HubContainers.canCheck(actual, currentSession, current)) throw HubIdentityException()
                val queued = currentApi.queueContainerAction(currentSession, actual, HubContainerAction.STATUS,
                    current, UUID.randomUUID().toString())
                val finished = awaitContainerJob(currentApi, currentSession, actual.id, queued.id,
                    HubContainerAction.STATUS, current.id, operation)
                val control = if (finished.state == "succeeded" && finished.exitCode == 0 &&
                    finished.result?.result == "ok") currentApi.containerControl(currentSession, actual.id, current.id) else null
                postUi {
                    if (operation != containerOperationId || session !== currentSession) return@postUi
                    containerBusy = false
                    containerControl = control?.takeIf { it.sourceStatus == "ok" &&
                        selectedContainerServerId == server.id && selectedContainerId == container.id }
                    containerControlElapsed = if (containerControl != null) SystemClock.elapsedRealtime() else 0L
                    containerMessage = if (containerControl != null) "Состояние подтверждено."
                        else "Состояние не подтвердилось. Проверьте Agent и разрешения контейнера."
                    showDashboard(refreshed)
                }
            } catch (error: Exception) {
                postUi {
                    if (operation != containerOperationId || session !== currentSession) return@postUi
                    containerBusy = false
                    containerControl = null
                    if (error is HubHttpException && error.statusCode == 401) {
                        returnToLogin("Сеанс завершён. Войдите снова.")
                        return@postUi
                    }
                    containerMessage = when (error) {
                        is HubIdentityException -> "Права или список контейнеров изменились. Обновите мониторинг."
                        is HubHttpException -> "Hub отклонил проверку: HTTP ${error.statusCode}."
                        else -> "Не удалось подтвердить состояние. Проверьте сеть и Agent."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun confirmContainerAction(latest: HubSnapshot, server: HubServer, container: HubContainer,
                                       action: HubContainerAction) {
        val currentSession = session ?: return
        val proof = containerControl
        if (containerBusy || !HubContainers.canMutate(server, currentSession, container, proof,
                SystemClock.elapsedRealtime() - containerControlElapsed)) {
            containerControl = null
            containerMessage = "Состояние изменилось или проверка устарела. Проверьте контейнер снова."
            showDashboard(latest)
            return
        }
        val confirmed = proof ?: return
        AlertDialog.Builder(this)
            .setTitle("${action.label} ${container.name}?")
            .setMessage("Сервер: ${server.name}. Docker ID: ${container.id}. " +
                "После действия проверьте состояние контейнера снова.")
            .setNegativeButton("Отмена", null)
            .setPositiveButton(action.label) { _, _ ->
                val active = session ?: return@setPositiveButton
                if (active !== currentSession || selectedContainerServerId != server.id ||
                    selectedContainerId != container.id || containerBusy ||
                    !HubContainers.canMutate(server, active, container, confirmed,
                        SystemClock.elapsedRealtime() - containerControlElapsed)) {
                    containerControl = null
                    containerMessage = "Состояние изменилось. Проверьте контейнер снова."
                    showDashboard(latest)
                    return@setPositiveButton
                }
                performContainerAction(latest, server, container, action, confirmed)
            }.show()
    }

    private fun performContainerAction(latest: HubSnapshot, server: HubServer, container: HubContainer,
                                       action: HubContainerAction, proof: HubContainerControl) {
        val currentApi = api ?: return
        val currentSession = session ?: return
        val proofElapsed = containerControlElapsed
        val operation = ++containerOperationId
        containerControl = null
        containerBusy = true
        containerMessage = "Отправляем действие ${action.label.lowercase(Locale.ROOT)}…"
        showDashboard(latest)
        containerWorker.execute {
            var submitted = false
            var accepted = false
            try {
                val refreshed = currentApi.snapshot(currentSession)
                val actual = refreshed.servers.firstOrNull { it.id == server.id } ?: throw HubIdentityException()
                val current = actual.containers?.docker?.containers?.firstOrNull { it.id == container.id }
                    ?: throw HubIdentityException()
                if (!HubContainers.canMutate(actual, currentSession, current, proof,
                        SystemClock.elapsedRealtime() - proofElapsed)) throw HubIdentityException()
                val currentControl = currentApi.containerControl(currentSession, server.id, container.id)
                if (currentControl != proof || currentControl.sourceStatus != "ok") throw HubIdentityException()
                val key = UUID.randomUUID().toString()
                submitted = true
                val queued = currentApi.queueContainerAction(currentSession, actual, action, current,
                    key, proof, SystemClock.elapsedRealtime() - proofElapsed)
                accepted = true
                val finished = awaitContainerJob(currentApi, currentSession, server.id, queued.id,
                    action, container.id, operation)
                postUi {
                    if (operation != containerOperationId || session !== currentSession) return@postUi
                    containerBusy = false
                    containerMessage = if (finished.state == "succeeded" && finished.exitCode == 0 &&
                        finished.result?.result == "ok")
                        "Действие выполнено. Проверьте состояние контейнера снова."
                    else "Исход действия не подтверждён. Проверьте состояние перед повтором."
                    showDashboard(refreshed)
                }
            } catch (error: Exception) {
                postUi {
                    if (operation != containerOperationId || session !== currentSession) return@postUi
                    containerBusy = false
                    if (error is HubHttpException && error.statusCode == 401) {
                        returnToLogin("Сеанс завершён. Проверьте состояние контейнера после входа.")
                        return@postUi
                    }
                    containerMessage = when {
                        accepted -> "Исход действия неизвестен. Проверьте состояние перед повтором."
                        submitted && error is HubHttpException && error.statusCode in setOf(400, 403, 404, 409) ->
                            "Hub отклонил действие до очереди: HTTP ${error.statusCode}. Проверьте разрешения."
                        submitted -> "Исход действия неизвестен. Проверьте состояние перед повтором."
                        else -> "Действие не отправлено. Проверьте состояние заново."
                    }
                    showDashboard(latest)
                }
            }
        }
    }

    private fun awaitContainerJob(api: HubApi, currentSession: HubSession, serverId: String,
                                  jobId: String, action: HubContainerAction, id: String,
                                  operation: Int): HubContainerJob {
        val deadline = SystemClock.elapsedRealtime() + 75_000
        while (true) {
            if (disposed || operation != containerOperationId || session !== currentSession)
                throw InterruptedException("Container view closed")
            val job = api.containerJob(currentSession, serverId, jobId, action, id)
            if (job.terminal) return job
            if (SystemClock.elapsedRealtime() >= deadline) throw java.io.IOException("Container job timeout")
            Thread.sleep(1_000)
        }
    }

    private fun renderIncidents(root: LinearLayout, incidents: List<HubIncident>, status: TextView) {
        val active = incidents.filter { it.state == "firing" }
        val history = incidents.filter { it.state == "resolved" }
        root.addView(label("Активные тревоги · ${active.size}", 20f))
        if (active.isEmpty()) root.addView(label("Активных тревог нет."))
        active.forEach { renderIncident(root, it, status) }
        root.addView(label("История восстановления", 20f))
        if (history.isEmpty()) root.addView(label("Завершённых событий пока нет."))
        history.forEach { renderIncident(root, it, status) }
        if (incidents.size >= 100) root.addView(label("Показаны последние 100 событий Hub.", 13f))
    }

    private fun renderIncident(root: LinearLayout, incident: HubIncident, status: TextView) {
        val title = HubMonitoring.incidentTitle(incident)
        root.addView(label("${incident.serverName} · $title", 17f))
        val timeline = if (incident.state == "resolved") {
            val end = incident.resolvedAt ?: incident.updatedAt
            "Восстановлено ${HubMonitoring.localStamp(end)} · начало ${HubMonitoring.localStamp(incident.openedAt)} · длилось ${duration(end - incident.openedAt)}"
        } else "Тревога с ${HubMonitoring.localStamp(incident.openedAt)} · обновлено ${HubMonitoring.localStamp(incident.updatedAt)}"
        root.addView(label(timeline, 13f))
        if (!incident.kind.startsWith("check:") && incident.currentValue != null && incident.threshold != null) {
            val (pattern, unit) = when {
                incident.kind == "offline" -> "%.0f" to " сек"
                incident.kind.startsWith("filesystem:") || incident.kind in setOf(
                    "high_cpu", "high_memory", "high_disk", "high_root_inodes",
                    "high_psi_cpu_some", "high_psi_memory_some", "high_psi_memory_full",
                    "high_psi_io_some", "high_psi_io_full", "high_cpu_iowait", "high_cpu_steal") -> "%.1f" to "%"
                else -> "%.0f" to ""
            }
            root.addView(label("Значение: ${formatValue(pattern, incident.currentValue)}$unit · порог: ${formatValue(pattern, incident.threshold)}$unit", 13f))
        }
        if (incident.acknowledgedAt != null) root.addView(label("Подтверждено ${HubMonitoring.localStamp(incident.acknowledgedAt)}", 13f))
        else if (incident.state == "firing" && session?.canAcknowledge(incident.serverId) == true) root.addView(Button(this).apply {
            text = "Подтвердить тревогу"
            isAllCaps = false
            setOnClickListener { confirmAcknowledge(incident, this, status) }
        })
    }

    private fun confirmAcknowledge(incident: HubIncident, button: Button, status: TextView) {
        if (session?.canAcknowledge(incident.serverId) != true) return
        AlertDialog.Builder(this)
            .setTitle("Подтвердить тревогу?")
            .setMessage("${incident.serverName}: ${HubMonitoring.incidentTitle(incident)}. Подтверждение отметит событие просмотренным. Тревога закроется после устранения причины.")
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Подтвердить") { _, _ ->
                val currentApi = api ?: return@setPositiveButton
                val currentSession = session ?: return@setPositiveButton
                if (!currentSession.canAcknowledge(incident.serverId)) return@setPositiveButton
                val generation = ++requestGeneration
                button.isEnabled = false
                status.text = "Подтверждаем тревогу…"
                worker.execute {
                    try {
                        if (disposed || generation != requestGeneration) return@execute
                        currentApi.acknowledge(currentSession, incident.id, incident.serverId)
                        val refreshed = currentApi.snapshot(currentSession)
                        postUi { if (generation == requestGeneration) showDashboard(refreshed) }
                    } catch (error: Exception) {
                        postUi {
                            if (generation != requestGeneration) return@postUi
                            if (isAccessFailure(error)) {
                                returnToLogin("Сеанс завершён или права доступа изменились. Войдите снова.")
                                return@postUi
                            }
                            status.text = if (error is HubHttpException)
                                "Не удалось подтвердить тревогу: HTTP ${error.statusCode}."
                            else "Не удалось подтвердить тревогу. Проверьте сеть."
                            button.isEnabled = true
                        }
                    }
                }
            }
            .show()
    }

    private fun percent(value: Double?): String =
        if (value == null) "—" else String.format(Locale.US, "%.1f%%", value)

    private fun formatValue(pattern: String, value: Double): String = String.format(Locale.US, pattern, value)

    private fun duration(seconds: Long): String = when {
        seconds < 0 -> "—"
        seconds < 60 -> "$seconds сек"
        seconds < 3600 -> "${seconds / 60} мин"
        else -> "${seconds / 3600} ч ${(seconds % 3600) / 60} мин"
    }

    private fun postUi(action: () -> Unit) {
        runOnUiThread { if (!disposed) action() }
    }

    private fun isAccessFailure(error: Exception): Boolean = error is HubIdentityException ||
        error is HubHttpException && error.statusCode in setOf(401, 403)

    private fun returnToLogin(notice: String) {
        val currentApi = api
        val currentSession = session
        requestGeneration++
        session = null
        api = null
        selectedTab = Tab.SERVERS
        selectedCheckServerId = null
        checkSummary = null
        checksError = null
        serviceOperationId++
        selectedServiceServerId = null
        serviceControl = null
        serviceBusy = false
        containerOperationId++
        selectedContainerServerId = null
        selectedContainerId = null
        containerControl = null
        containerBusy = false
        filesystemOperationId++
        selectedFilesystemServerId = null
        filesystemState = null
        filesystemBusy = false
        showLogin(notice)
        if (currentApi != null && currentSession != null) {
            worker.execute { runCatching { currentApi.logout(currentSession.token) } }
        }
    }

    override fun onDestroy() {
        disposed = true
        requestGeneration++
        session = null
        api = null
        worker.shutdown()
        serviceWorker.shutdownNow()
        containerWorker.shutdownNow()
        filesystemWorker.shutdownNow()
        super.onDestroy()
    }
}
