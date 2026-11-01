/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

internal object PanelFileTransferScript {
    val source = """
(() => {
  if (globalThis.__sovagridNativeFilesInstalled) return;
  const bridge = globalThis.sovagridNativeFiles || globalThis.webkit?.messageHandlers?.sovagridNativeFiles;
  if (!bridge || typeof bridge.postMessage !== "function") return;
  globalThis.__sovagridNativeFilesInstalled = true;
  const pending = new Map();
  let busy = false;
  const maxBytes = 32 * 1024 * 1024 * 1024;
  globalThis.__sovagridFileReply = (id, step, ok) => {
    const key = id + ":" + step;
    const entry = pending.get(key);
    if (!entry) return;
    pending.delete(key); clearTimeout(entry.timer);
    if (ok === true) entry.resolve(); else entry.reject(new Error("Native save cancelled"));
  };
  function send(message, step) {
    return new Promise((resolve, reject) => {
      const key = message.id + ":" + step;
      const timer = setTimeout(() => {
        pending.delete(key); reject(new Error("Native save timed out"));
      }, 120000);
      pending.set(key, {resolve, reject, timer});
      bridge.postMessage(JSON.stringify(message));
    });
  }
  document.addEventListener("click", (event) => {
    const link = event.target?.closest?.("a[download]");
    if (!link || !link.hasAttribute("download")) return;
    let url;
    try { url = new URL(link.href, location.href); } catch { return; }
    const local = url.protocol === "http:" && url.origin === location.origin && !url.username && !url.password;
    const blob = url.protocol === "blob:" && url.origin === location.origin;
    if (!local && !blob) return;
    event.preventDefault();
    if (busy) return;
    busy = true;
    const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, "0")).join("");
    const controller = new AbortController();
    (async () => {
      let reader;
      try {
        await send({op:"start", id, filename:link.download || "download.bin"}, "start");
        const response = await fetch(url.href, {credentials:"same-origin", cache:"no-store", redirect:"error", signal:controller.signal});
        if (!response.ok || !response.body) throw new Error("Download failed");
        const header = response.headers.get("Content-Length");
        const size = !response.headers.get("Content-Encoding") && header && /^[0-9]+$/.test(header) ? Number(header) : null;
        if (size !== null && (!Number.isSafeInteger(size) || size > maxBytes)) throw new Error("File too large");
        await send({op:"metadata", id, bytes:size}, "metadata");
        reader = response.body.getReader();
        let count = 0, index = 0;
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          for (let offset = 0; offset < item.value.length; offset += 65536) {
            const bytes = item.value.subarray(offset, offset + 65536);
            count += bytes.length;
            if (count > maxBytes) throw new Error("File too large");
            let raw = "";
            for (let n = 0; n < bytes.length; n += 8192) raw += String.fromCharCode(...bytes.subarray(n, n + 8192));
            await send({op:"chunk", id, index, data:btoa(raw)}, String(index));
            index++;
          }
        }
        if (size !== null && size !== count) throw new Error("Incomplete download");
        await send({op:"complete", id, bytes:count}, "complete");
      } catch {
        bridge.postMessage(JSON.stringify({op:"cancel", id}));
      } finally {
        // WebKit can leave cancel() pending after aborting an exhausted HTTP
        // stream. Release the completed transfer before best-effort cleanup.
        busy = false;
        controller.abort();
        if (reader) { try { void reader.cancel().catch(() => {}); } catch {} }
      }
    })();
  }, true);
})();
"""
}
