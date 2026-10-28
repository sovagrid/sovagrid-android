/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.app.Activity
import android.app.Instrumentation
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.os.SystemClock
import android.system.Os
import android.view.View
import android.view.ViewGroup
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONObject
import org.sovagrid.ssh.SshClientCore
import java.io.File
import java.security.KeyStore
import java.util.UUID

/** Device-only Keystore test. No test endpoint or exported hook is added to the application. */
class SshKeyVaultInstrumentation : Instrumentation() {
    private var mode = "full"
    private var publicSaveStage = "opening public key"
    private var publicSaveName = ""
    private var publicSaveBytes = 0
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
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
                    else -> updatePersistence(vault)
                }
                finish(Activity.RESULT_OK, Bundle().apply {
                    putString("result", "$mode passed")
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
                putString("error", "${if (mode == "public-save-ui") publicSaveStage else stage}: ${error.javaClass.simpleName}")
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
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
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
        val up = MotionEvent.obtain(time, time + 50, MotionEvent.ACTION_UP, bounds.exactCenterX(), bounds.exactCenterY(), 0)
        down.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        up.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        return try { uiAutomation.injectInputEvent(down, true) && uiAutomation.injectInputEvent(up, true) }
        finally { down.recycle(); up.recycle() }
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
}
