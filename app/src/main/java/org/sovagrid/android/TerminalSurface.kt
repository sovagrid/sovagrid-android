/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.WebViewAssetLoader
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Offline xterm.js screen. SSH credentials and host key verification never enter this WebView. */
class TerminalSurface(
    context: Context,
    private val onInput: (String) -> Unit,
    private val onResize: (Int, Int) -> Unit,
    private val onFailure: () -> Unit
) : WebView(context) {
    private val closed = AtomicBoolean(false)
    private val scheduled = AtomicBoolean(false)
    private val output = ArrayBlockingQueue<String>(128)
    private var pageReady = false
    private var writeInFlight = false

    init {
        setBackgroundColor(if (AppTheme.isDark(context)) Color.rgb(16, 28, 43) else Color.rgb(245, 248, 252))
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        val assets = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(context))
            .build()
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = false
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.blockNetworkLoads = true
        settings.javaScriptCanOpenWindowsAutomatically = false
        settings.setSupportMultipleWindows(false)
        settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
        webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true

            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                val uri = request.url
                return if (uri.scheme == "https" && uri.host == "appassets.androidplatform.net" &&
                    uri.encodedPath?.startsWith("/assets/terminal/") == true) {
                    assets.shouldInterceptRequest(uri)
                } else {
                    WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream(ByteArray(0)))
                }
            }

            override fun onRenderProcessGone(view: WebView, detail: android.webkit.RenderProcessGoneDetail): Boolean {
                onFailure()
                return true
            }
        }
        addJavascriptInterface(Bridge(), "AndroidTerminal")
        loadUrl("https://appassets.androidplatform.net/assets/terminal/index.html")
    }

    /** Backpressure keeps a fast command from filling the Android UI queue. */
    fun enqueueFromReader(text: String) {
        while (!closed.get()) {
            try {
                if (output.offer(text, 250, TimeUnit.MILLISECONDS)) {
                    scheduleDrain()
                    return
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
        }
    }

    fun writeLocal(text: String) {
        if (closed.get()) return
        if (output.offer(text)) scheduleDrain()
    }

    fun paste(text: String) {
        if (closed.get() || !pageReady || text.length > 16_384) return
        evaluateJavascript("window.sovaPaste(${JSONObject.quote(text)})", null)
    }

    fun focusTerminal() {
        if (!closed.get() && pageReady) evaluateJavascript("window.sovaFocus()", null)
    }

    private fun scheduleDrain() {
        if (scheduled.compareAndSet(false, true)) {
            post {
                scheduled.set(false)
                drain()
            }
        }
    }

    private fun drain() {
        if (closed.get() || !pageReady || writeInFlight) return
        val chunk = output.poll() ?: return
        writeInFlight = true
        evaluateJavascript("window.sovaWrite(${JSONObject.quote(chunk)})", null)
    }

    fun closeSurface() {
        if (!closed.compareAndSet(false, true)) return
        output.clear()
        removeJavascriptInterface("AndroidTerminal")
        stopLoading()
        (parent as? ViewGroup)?.removeView(this)
        destroy()
    }

    private inner class Bridge {
        @JavascriptInterface fun ready(columns: Int, rows: Int) {
            post {
                if (closed.get()) return@post
                pageReady = true
                contentDescription = "SSH-терминал: $columns столбцов, $rows строк"
                if (columns in 2..500 && rows in 2..300) onResize(columns, rows)
                drain()
            }
        }

        @JavascriptInterface fun resize(columns: Int, rows: Int) {
            post {
                if (!closed.get() && columns in 2..500 && rows in 2..300) {
                    contentDescription = "SSH-терминал: $columns столбцов, $rows строк"
                    onResize(columns, rows)
                }
            }
        }

        @JavascriptInterface fun input(data: String) {
            if (data.length > 32_768) return
            post { if (!closed.get()) onInput(data) }
        }

        @JavascriptInterface fun drained() {
            post {
                if (closed.get()) return@post
                writeInFlight = false
                drain()
            }
        }
    }
}
