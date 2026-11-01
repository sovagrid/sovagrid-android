/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.Instrumentation
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.ContentValues
import android.graphics.Rect
import android.os.Bundle
import android.os.SystemClock
import android.system.Os
import android.os.CancellationSignal
import android.provider.MediaStore
import android.view.View
import android.view.ViewGroup
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONObject
import org.sovagrid.ssh.SshClientCore
import org.sovagrid.ssh.Endpoint
import android.net.Uri
import android.webkit.WebView
import androidx.webkit.WebViewFeature
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.io.File
import java.security.KeyStore
import java.util.UUID

/** Device-only Keystore test. No test endpoint or exported hook is added to the application. */
class SshKeyVaultInstrumentation : Instrumentation() {
    private var mode = "full"
    private var publicSaveStage = "opening public key"
        set(value) {
            field = value
            if (mode.startsWith("panel-")) android.util.Log.d("SovaGridUITest", value)
        }
    private var publicSaveName = ""
    private var publicSaveBytes = 0
    private var fixtureArguments = Bundle()
    private var fixturePublicKey: String? = null
    private var fixtureBrowserState: String? = null
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        this.fixtureArguments = arguments ?: Bundle()
        mode = arguments?.getString("mode") ?: "full"
        start()
    }

    override fun onStart() {
        var keyId: String? = null
        val vault = SshKeyVault(targetContext)
        var stage = "initialization"
        try {
            SshClientCore() // Exercise Keystore after SSHJ installs its bundled crypto provider.
            if (mode != "full") {
                when (mode) {
                    "public-ui" -> publicCopy(vault)
                    "public-save-ui" -> publicSave(vault)
                    "panel-files-setup" -> panelFilesSetup(vault)
                    "panel-files-ui" -> panelFiles(vault)
                    "panel-restore-ui" -> panelRestore(vault)
                    else -> updatePersistence(vault)
                }
                finish(Activity.RESULT_OK, Bundle().apply {
                    putString("result", "$mode passed")
                    fixturePublicKey?.let { putString("public_key", it) }
                    if (mode == "public-save-ui") {
                        putString("filename", publicSaveName)
                        putInt("public_bytes", publicSaveBytes)
                        putBoolean("exact_public_key_with_final_newline", true)
                    }
                })
                return
            }
            val before = vault.all().map { it.id }.toSet()
            stage = "generation"
            val created = vault.create("Vault test ${UUID.randomUUID().toString().take(8)}")
            keyId = created.id
            check(created.publicKey.startsWith("ssh-ed25519 "))
            check(SshKeyVault(targetContext).publicKey(created.id) == created)
            check(vault.privateKeyText(created.id).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
            val file = File(targetContext.noBackupFilesDir, "ssh-keys/${created.id}.json")
            check((Os.stat(file.path).st_mode and 0x1ff) == 0x180)
            check((Os.stat(file.parentFile!!.path).st_mode and 0x1ff) == 0x1c0)
            val original = file.readBytes()
            check(!String(original, Charsets.UTF_8).contains("PRIVATE KEY"))
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            check(store.getKey("org.sovagrid.ssh.${created.id}", null).encoded == null)
            val modified = JSONObject(String(original, Charsets.UTF_8)).put("label", "Tampered metadata").toString().toByteArray()
            stage = "tamper rejection"
            file.writeBytes(modified)
            check(runCatching { vault.privateKeyText(created.id) }.isFailure)
            check(file.readBytes().contentEquals(modified)) // Failure must not silently generate a replacement.
            file.writeBytes(original)
            check(vault.publicKey(created.id) == created)
            stage = "deletion"
            vault.delete(created.id)
            check(!file.exists())
            check(!store.containsAlias("org.sovagrid.ssh.${created.id}"))
            check(runCatching { vault.privateKeyText(created.id) }.isFailure)
            check(vault.all().map { it.id }.toSet() == before)
            keyId = null
            finish(Activity.RESULT_OK, Bundle().apply { putString("result", "Keystore generation, persistence, tamper rejection and deletion passed") })
        } catch (error: Exception) {
            finish(Activity.RESULT_CANCELED, Bundle().apply {
                putString("error", "${if (mode == "public-save-ui" || mode.startsWith("panel-")) publicSaveStage else stage}: ${error.javaClass.simpleName}")
                fixtureBrowserState?.let { putString("browser_state", it) }
            })
        } finally { keyId?.let { runCatching { vault.delete(it) } } }
    }

    private fun publicSave(vault: SshKeyVault) {
        val key = vault.create("Public save UI ${UUID.randomUUID().toString().take(8)}")
        val basename = "sovagrid-public-ui-${UUID.randomUUID()}"
        val filename = "$basename.pub"
        val path = "/sdcard/Download/$filename"
        var activity: Activity? = null
        try {
            check(shell("ls $path").isEmpty())
            val opened = startActivitySync(Intent(targetContext, SshKeysActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            activity = opened
            waitForIdleSync()
            runOnMainSync {
                fun find(view: View): View? {
                    if (view.contentDescription == "Показать публичный ключ: ${key.label}") return view
                    if (view is ViewGroup) for (index in 0 until view.childCount) find(view.getChildAt(index))?.let { return it }
                    return null
                }
                check(find(opened.window.decorView)?.performClick() == true)
            }
            publicSaveStage = "opening system create-document picker"
            check(waitNode { it.text?.toString() == "Сохранить публичный .pub" }
                ?.let(::clickNode) == true)
            check(waitNode { it.packageName?.toString()?.contains("documentsui") == true } != null)
            publicSaveStage = "selecting Downloads"
            val roots = findNode(uiAutomation.rootInActiveWindow) {
                it.contentDescription?.toString() in listOf("Show roots", "Open navigation drawer")
            }
            if (roots != null) {
                check(clickNode(roots))
                publicSaveStage = "finding Downloads root"
                check(waitNode { it.text?.toString() in listOf("Downloads", "Загрузки") } != null)
                Thread.sleep(300)
                val candidates = uiAutomation.rootInActiveWindow?.findAccessibilityNodeInfosByText("Downloads").orEmpty()
                    .filter { it.isVisibleToUser && it.text?.toString() == "Downloads" }
                publicSaveStage = "touching Downloads root (${candidates.size})"
                check(candidates.lastOrNull()?.let(::touchNode) == true)
            }
            publicSaveStage = "entering public filename"
            val name = waitNode { it.isEditable && it.className?.toString() == "android.widget.EditText" }
                ?: error("Filename field unavailable")
            check(name.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, filename)
            }))
            publicSaveStage = "saving through DocumentsUI"
            check(waitNode {
                val text = it.text?.toString()
                text.equals("Save", ignoreCase = true) || text == "Сохранить"
            }?.let(::clickNode) == true)
            publicSaveStage = "reading saved public bytes"
            val expected = (key.publicKey + "\n").toByteArray(Charsets.UTF_8)
            val deadline = System.currentTimeMillis() + 10_000
            var actual = ByteArray(0)
            while (System.currentTimeMillis() < deadline) {
                actual = shellBytes("cat $path")
                if (actual.contentEquals(expected)) break
                Thread.sleep(100)
            }
            publicSaveStage = "reading saved public bytes (actual=${actual.size}, expected=${expected.size})"
            check(actual.contentEquals(expected))
            check(!actual.toString(Charsets.UTF_8).contains("PRIVATE KEY"))
            val exported = shell("find /sdcard/Download -maxdepth 1 -type f -name $basename*")
                .lineSequence().filter { it.isNotBlank() }.toList()
            check(exported == listOf(path))
            publicSaveName = filename
            publicSaveBytes = actual.size
            publicSaveStage = "public export cleanup"
            shell("rm -f $path")
            check(shell("ls $path").isEmpty())
        } finally {
            // Only the uniquely generated fixture prefix is removed, including
            // an extension the provider may have appended on a failed test.
            shell("find /sdcard/Download -maxdepth 1 -type f -name $basename*")
                .lineSequence().filter { it.startsWith("/sdcard/Download/$basename") && !it.any(Char::isWhitespace) }
                .forEach { shell("rm -f $it") }
            uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
            activity?.let { runOnMainSync { it.finish() } }
            vault.delete(key.id)
        }
    }

    // UiAutomation executes argv directly; generated fixture paths contain only safe ASCII.
    // Keep shell quoting, redirection and operators out of these commands.
    private fun shell(command: String): String = shellBytes(command).toString(Charsets.UTF_8).trim()

    private fun shellBytes(command: String): ByteArray = android.os.ParcelFileDescriptor.AutoCloseInputStream(
        uiAutomation.executeShellCommand(command)).use { it.readBytes() }

    private fun findNode(root: AccessibilityNodeInfo?, predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        if (root == null) return null
        if (root.isVisibleToUser && predicate(root)) return root
        for (index in 0 until root.childCount) findNode(root.getChild(index), predicate)?.let { return it }
        return null
    }

    private fun waitNode(predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        val deadline = SystemClock.uptimeMillis() + 10_000
        while (SystemClock.uptimeMillis() < deadline) {
            findNode(uiAutomation.rootInActiveWindow, predicate)?.let { return it }
            Thread.sleep(100)
        }
        return null
    }

    private fun clickNode(node: AccessibilityNodeInfo): Boolean {
        var candidate: AccessibilityNodeInfo? = node
        repeat(6) {
            if (candidate?.isClickable == true) return candidate?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
            candidate = candidate?.parent
        }
        return false
    }

    private fun touchNode(node: AccessibilityNodeInfo): Boolean {
        val bounds = Rect().also(node::getBoundsInScreen)
        val time = SystemClock.uptimeMillis()
        val down = MotionEvent.obtain(time, time, MotionEvent.ACTION_DOWN, bounds.exactCenterX(), bounds.exactCenterY(), 0)
        down.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        return try {
            if (!uiAutomation.injectInputEvent(down, true)) false else {
                SystemClock.sleep(60)
                val up = MotionEvent.obtain(time, SystemClock.uptimeMillis(), MotionEvent.ACTION_UP,
                    bounds.exactCenterX(), bounds.exactCenterY(), 0)
                up.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
                try { uiAutomation.injectInputEvent(up, true) } finally { up.recycle() }
            }
        } finally { down.recycle() }
    }

    // Older DocumentsUI selection filters require a finger tool type; the
    // simple MotionEvent factory (and old adb input) leaves it UNKNOWN.
    private fun fingerTouchNode(node: AccessibilityNodeInfo): Boolean {
        val bounds = Rect().also(node::getBoundsInScreen)
        val downTime = SystemClock.uptimeMillis()
        val pointer = arrayOf(MotionEvent.PointerProperties().apply {
            id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER
        })
        val coords = arrayOf(MotionEvent.PointerCoords().apply {
            x = bounds.exactCenterX(); y = bounds.exactCenterY(); pressure = 1f; size = 1f
        })
        fun event(action: Int) = MotionEvent.obtain(downTime, SystemClock.uptimeMillis(), action,
            1, pointer, coords, 0, 0, 1f, 1f, 0, 0,
            android.view.InputDevice.SOURCE_TOUCHSCREEN, 0)
        val down = event(MotionEvent.ACTION_DOWN)
        return try {
            check(down.getToolType(0) == MotionEvent.TOOL_TYPE_FINGER)
            if (!uiAutomation.injectInputEvent(down, true)) false else {
                SystemClock.sleep(60)
                val up = event(MotionEvent.ACTION_UP)
                try { uiAutomation.injectInputEvent(up, true) } finally { up.recycle() }
            }
        } finally { down.recycle() }
    }

    private fun publicCopy(vault: SshKeyVault) {
        val key = vault.create("Public UI ${UUID.randomUUID().toString().take(8)}")
        var activity: Activity? = null
        try {
            val opened = startActivitySync(Intent(targetContext, SshKeysActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            activity = opened
            waitForIdleSync()
            runOnMainSync {
                fun find(view: View): View? {
                    if (view.contentDescription == "Показать публичный ключ: ${key.label}") return view
                    if (view is ViewGroup) for (index in 0 until view.childCount) find(view.getChildAt(index))?.let { return it }
                    return null
                }
                check(find(opened.window.decorView)?.performClick() == true)
            }
            val deadline = System.currentTimeMillis() + 10_000
            var clicked = false
            while (System.currentTimeMillis() < deadline && !clicked) {
                val root = uiAutomation.rootInActiveWindow
                val candidates = root?.findAccessibilityNodeInfosByText("Копировать публичный ключ").orEmpty()
                clicked = candidates.firstOrNull { it.text == "Копировать публичный ключ" }
                    ?.performAction(AccessibilityNodeInfo.ACTION_CLICK) == true
                if (!clicked) Thread.sleep(100)
            }
            check(clicked)
            waitForIdleSync()
            runOnMainSync {
                val clipboard = targetContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                check(clipboard.primaryClip?.getItemAt(0)?.text?.toString() == key.publicKey)
                if (android.os.Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                else clipboard.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
            }
        } finally {
            activity?.let { runOnMainSync { it.finish() } }
            vault.delete(key.id)
        }
    }

    private fun updatePersistence(vault: SshKeyVault) {
        val marker = targetContext.getSharedPreferences("sovagrid_key_update_test", 0)
        when (mode) {
            "prepare-update" -> {
                check(marker.getString("id", null) == null)
                val key = vault.create("Disposable update test")
                check(marker.edit().putString("id", key.id).putString("public", key.publicKey).commit())
            }
            "verify-update" -> {
                val id = marker.getString("id", null) ?: error("Missing update marker")
                try {
                    check(vault.publicKey(id).publicKey == marker.getString("public", null))
                    check(vault.privateKeyText(id).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
                } finally {
                    vault.delete(id)
                    check(marker.edit().clear().commit())
                }
            }
            else -> error("Unknown test mode")
        }
    }

    private fun panelFilesSetup(vault: SshKeyVault) {
        val marker = targetContext.getSharedPreferences("sovagrid_panel_file_test", 0)
        check(!marker.contains("key"))
        val username = fixtureArguments.getString("username") ?: error("Fixture username required")
        val pin = fixtureArguments.getString("pin") ?: error("Fixture public host key required")
        val key = vault.create("Disposable panel file fixture")
        val store = HostStore(targetContext)
        val server = store.add("Disposable panel file fixture", Endpoint("10.0.2.2", 22224, username))
        check(store.setPin(server.id, pin))
        check(marker.edit().putString("key", key.id).putString("server", server.id).commit())
        fixturePublicKey = key.publicKey
    }

    private fun panelFiles(vault: SshKeyVault) {
        val marker = targetContext.getSharedPreferences("sovagrid_panel_file_test", 0)
        val key = marker.getString("key", null) ?: error("Missing fixture key")
        val server = marker.getString("server", null) ?: error("Missing fixture server")
        var activity: Activity? = null
        try {
            publicSaveStage = "opening actual panel through local SSH"
            runOnMainSync {
                EphemeralSshHandoff.offer(SessionSshHandoff(server,
                    SessionSshCredential.Key(Uri.parse(SshKeyReference.uri(key)), charArrayOf()), null))
            }
            activity = startActivitySync(Intent(targetContext, PanelActivity::class.java)
                .putExtra("server_id", server).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            check(waitNode { it.text?.toString() == "LOCAL PANEL FIXTURE" } != null)
            fixtureBrowserState = "message_listener=${WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)} " +
                panelJavaScript(activity, "JSON.stringify({installed:globalThis.__sovagridNativeFilesInstalled,bridge:typeof globalThis.sovagridNativeFiles?.postMessage,origin:location.origin,width:innerWidth,height:innerHeight})")
            for ((label, filename) in listOf("Download private HTTP" to "panel-native.bin", "Download binary Blob" to "panel-blob.bin")) {
                publicSaveStage = "starting $filename"
                val link = waitNode { it.text?.toString() == label } ?: error("Download control missing")
                val bounds = Rect().also(link::getBoundsInScreen)
                check(touchNode(link))
                publicSaveStage = "confirming native download $filename"
                fixtureBrowserState += " touch="+bounds.toShortString()+" "+panelJavaScript(activity,
                    "JSON.stringify({installed:globalThis.__sovagridNativeFilesInstalled,bridge:typeof globalThis.sovagridNativeFiles?.postMessage})")
                check(waitNode { it.text?.toString().equals("Скачать", ignoreCase = true) }?.let(::clickNode) == true)
                publicSaveStage = "waiting system save picker for $filename"
                check(waitNode { it.packageName?.toString()?.contains("documentsui") == true } != null)
                publicSaveStage = "selecting Downloads for $filename"
                findNode(uiAutomation.rootInActiveWindow) {
                    it.contentDescription?.toString() in listOf("Show roots", "Open navigation drawer")
                }?.let { check(clickNode(it)) }
                val downloads = waitNode { it.text?.toString() in listOf("Downloads", "Загрузки") }
                if (downloads != null) check(touchNode(downloads))
                val name = waitNode { it.isEditable && it.className?.toString() == "android.widget.EditText" }
                    ?: error("Filename field unavailable")
                check(name.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                    putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, filename)
                }))
                publicSaveStage = "saving $filename through system picker"
                check(waitNode { it.text?.toString().equals("Save", true) || it.text?.toString() == "Сохранить" }
                    ?.let(::clickNode) == true)
                check(waitNode { it.text?.toString() == "LOCAL PANEL FIXTURE" } != null)
                val bytes = shellBytes("cat /sdcard/Download/$filename")
                val expected = if (filename == "panel-native.bin")
                    byteArrayOf(0, 1, 2, 0, -1, -128) + ByteArray(200000) { (it % 251).toByte() }
                    else ByteArray(140003) { (it % 251).toByte() }
                check(bytes.contentEquals(expected))
            }
            publicSaveStage = "opening actual WebView upload chooser"
            check(waitNode { it.text?.toString()?.contains("Choose downloaded file") == true }?.let(::touchNode) == true)
            check(waitNode { it.packageName?.toString()?.contains("documentsui") == true } != null)
            // Older DocumentsUI exposes both the folder heading and its drawer
            // entry as "Downloads". Select the last visible match, as in publicSave().
            if (findNode(uiAutomation.rootInActiveWindow) { it.text?.toString() == "panel-native.bin" } == null) {
                findNode(uiAutomation.rootInActiveWindow) {
                    it.contentDescription?.toString() in listOf("Show roots", "Open navigation drawer")
                }?.let { check(clickNode(it)) }
                Thread.sleep(300)
                val downloads = uiAutomation.rootInActiveWindow?.findAccessibilityNodeInfosByText("Downloads").orEmpty()
                    .filter { it.isVisibleToUser && it.text?.toString() == "Downloads" }
                check(downloads.lastOrNull()?.let(::touchNode) == true)
            }
            publicSaveStage = "selecting saved binary for WebView input"
            if (android.os.Build.VERSION.SDK_INT <= 30) {
                // The old grid separates preview, selection and activation
                // hotspots. Use its standard list row for an unambiguous tap.
                findNode(uiAutomation.rootInActiveWindow) {
                    it.contentDescription?.toString() in listOf("List view", "Список")
                }?.let { check(clickNode(it)) }
            }
            check(waitNode { it.text?.toString() == "panel-native.bin" && !it.isEditable }?.let {
                val selectedBounds = Rect().also(it::getBoundsInScreen)
                fixtureBrowserState += " picked="+it.className+":"+selectedBounds.toShortString()
                if (android.os.Build.VERSION.SDK_INT <= 30) {
                    fingerTouchNode(it)
                } else clickNode(it) || touchNode(it)
            } == true)
            Thread.sleep(300)
            if (uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true) {
                findNode(uiAutomation.rootInActiveWindow) {
                    it.text?.toString() in listOf("Open", "OPEN", "Select", "SELECT", "Открыть", "Выбрать") ||
                        it.contentDescription?.toString() in listOf("Open", "Select", "Открыть", "Выбрать")
                }?.let { check(clickNode(it)) }
            }
            publicSaveStage = "checking exact uploaded bytes through private content provider"
            val uploaded = waitNode { it.text?.toString() == "UPLOAD_OK 200006" }
            if (uploaded == null) {
                fixtureBrowserState += " upload="+panelJavaScript(activity,
                    "JSON.stringify({result:document.querySelector('#result').textContent,file:document.querySelector('#upload').files[0]?.name,size:document.querySelector('#upload').files[0]?.size,subtle:typeof crypto.subtle})")
                fixtureBrowserState += " picker="+activity.javaClass.getDeclaredField("uploadPickerActive").let {
                    it.isAccessible = true; it.get(activity)
                }+" snapshots="+activity.javaClass.getDeclaredField("uploadFiles").let {
                    it.isAccessible = true; (it.get(activity) as Collection<*>).size
                }+" window="+uiAutomation.rootInActiveWindow?.packageName
                val labels = mutableListOf<String>()
                fun describe(node: AccessibilityNodeInfo?) {
                    if (node == null) return
                    if (node.isVisibleToUser && (node.text != null || node.contentDescription != null))
                        labels.add("${node.text ?: node.contentDescription}[enabled=${node.isEnabled},selected=${node.isSelected}]")
                    for (index in 0 until node.childCount) describe(node.getChild(index))
                }
                describe(uiAutomation.rootInActiveWindow)
                fixtureBrowserState += " picker_labels="+labels.take(24).joinToString("|")
                uiAutomation.takeScreenshot()?.let { screenshot ->
                    File(targetContext.cacheDir, "panel-picker-diagnostic.png").outputStream().use {
                        screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)
                    }
                    screenshot.recycle()
                }
            }
            check(uploaded != null)
        } finally {
            if (uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true) {
                uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
                Thread.sleep(200)
            }
            activity?.let { runOnMainSync { it.finish() } }
            shell("rm -f /sdcard/Download/panel-native.bin")
            shell("rm -f /sdcard/Download/panel-blob.bin")
            HostStore(targetContext).remove(server)
            vault.delete(key)
            check(marker.edit().clear().commit())
        }
    }

    private fun panelRestore(vault: SshKeyVault) {
        val marker = targetContext.getSharedPreferences("sovagrid_panel_file_test", 0)
        val key = marker.getString("key", null) ?: error("Missing fixture key")
        val server = marker.getString("server", null) ?: error("Missing fixture server")
        val resolver = targetContext.contentResolver
        var activity: Activity? = null
        var uri: Uri? = null
        try {
            publicSaveStage = "creating synthetic 8MiB regular restore document"
            uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, "panel-restore.bin")
                put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
                put(MediaStore.MediaColumns.RELATIVE_PATH, "Download")
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }) ?: error("Synthetic document unavailable")
            val size = 8 * 1024 * 1024 + 23
            resolver.openOutputStream(uri, "w")!!.use { output ->
                var offset = 0
                while (offset < size) {
                    val chunk = ByteArray(minOf(65536, size-offset)) { ((offset + it) % 251).toByte() }
                    output.write(chunk); offset += chunk.size
                }
            }
            resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
            publicSaveStage = "checking retained regular FD, ranges, mutation and release"
            val proof = PanelRestoreFiles()
            val selected = proof.add(resolver, uri, CancellationSignal())
            try {
            publicSaveStage = "checking retained FD size"
            check(selected.size == size.toLong())
            publicSaveStage = "checking retained FD bytes at nonzero offset"
            check(proof.read(selected.handle, 4_194_301, 64).contentEquals(ByteArray(64) { ((4_194_301+it)%251).toByte() }))
            publicSaveStage = "checking retained FD range refusal"
            check(runCatching { proof.read(selected.handle, -1, 1) }.isFailure)
            check(runCatching { proof.read(selected.handle, size.toLong(), 1) }.isFailure)
            check(runCatching { proof.read(selected.handle, 0, 262145) }.isFailure)
            resolver.openFileDescriptor(uri, "rw")!!.use { fd -> Os.pwrite(fd.fileDescriptor, byteArrayOf(1), 0, 1, 0) }
            publicSaveStage = "checking retained FD mutation refusal"
            check(runCatching { proof.read(selected.handle, 0, 1) }.isFailure)
            } finally { proof.close() }
            check(runCatching { proof.read(selected.handle, 0, 1) }.isFailure)
            resolver.openFileDescriptor(uri, "rw")!!.use { fd -> Os.pwrite(fd.fileDescriptor, byteArrayOf(0), 0, 1, 0) }
            publicSaveStage = "opening actual restore panel through SSH"
            runOnMainSync {
                EphemeralSshHandoff.offer(SessionSshHandoff(server,
                    SessionSshCredential.Key(Uri.parse(SshKeyReference.uri(key)), charArrayOf()), null))
            }
            activity = startActivitySync(Intent(targetContext, PanelActivity::class.java)
                .putExtra("server_id", server).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            check(waitNode { it.text?.toString() == "NATIVE_RESTORE_READY" } != null)
            publicSaveStage = "opening dedicated native restore picker"
            check(waitNode { it.text?.toString() == "Choose backup files" }?.let(::touchNode) == true)
            check(waitNode { it.packageName?.toString()?.contains("documentsui") == true } != null)
            if (findNode(uiAutomation.rootInActiveWindow) { it.text?.toString() == "panel-restore.bin" } == null) {
                findNode(uiAutomation.rootInActiveWindow) {
                    it.contentDescription?.toString() in listOf("Show roots", "Open navigation drawer")
                }?.let { check(clickNode(it)) }
                val downloads = waitNode { it.text?.toString() == "Downloads" } ?: error("Downloads unavailable")
                check(touchNode(downloads))
            }
            findNode(uiAutomation.rootInActiveWindow) { it.contentDescription?.toString() == "List view" }
                ?.let { check(clickNode(it)) }
            val file = waitNode { it.text?.toString() == "panel-restore.bin" } ?: error("Synthetic restore document missing")
            check(fingerTouchNode(file))
            Thread.sleep(200)
            if (uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true) {
                findNode(uiAutomation.rootInActiveWindow) {
                    it.text?.toString() in listOf("Open", "OPEN", "Select", "SELECT", "Открыть", "Выбрать")
                }?.let { check(clickNode(it)) }
            }
            publicSaveStage = "hashing bounded native slices and verifying explicit release"
            val deadline = SystemClock.uptimeMillis() + 30000
            var completed = false
            while (SystemClock.uptimeMillis() < deadline) {
                if (findNode(uiAutomation.rootInActiveWindow) { it.text?.toString() == "RESTORE_OK" } != null) {
                    completed = true; break
                }
                Thread.sleep(100)
            }
            fixtureBrowserState = panelJavaScript(activity, "document.querySelector('#result').textContent")
            check(completed)
            runOnMainSync {
                check(activity.javaClass.getDeclaredField("restoreFiles").let { it.isAccessible = true; it.get(activity) } == null)
            }
        } finally {
            if (uiAutomation.rootInActiveWindow?.packageName?.toString()?.contains("documentsui") == true)
                uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
            activity?.let { runOnMainSync { it.finish() } }
            uri?.let { resolver.delete(it, null, null) }
            HostStore(targetContext).remove(server); vault.delete(key)
            check(marker.edit().clear().commit())
        }
    }

    private fun panelJavaScript(activity: Activity, expression: String): String {
        val result = AtomicReference<String>()
        val latch = CountDownLatch(1)
        runOnMainSync {
            fun find(view: View): WebView? {
                if (view is WebView) return view
                if (view is ViewGroup) for (i in 0 until view.childCount) find(view.getChildAt(i))?.let { return it }
                return null
            }
            val view = find(activity.window.decorView) ?: error("Panel WebView unavailable")
            view.evaluateJavascript(expression) { value -> result.set(value); latch.countDown() }
        }
        check(latch.await(10, TimeUnit.SECONDS))
        return result.get()
    }
}
