/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

internal object PanelRestoreScript {
    fun source(session: String, origin: String): String {
        require(Regex("[a-f0-9]{32}").matches(session))
        require(Regex("http://127[.]0[.]0[.]1:[0-9]{1,5}").matches(origin))
        return template.replace("__NATIVE_SESSION__", session).replace("__NATIVE_ORIGIN__", origin)
    }
    val template = """
(() => {
  const session = "__NATIVE_SESSION__", origin = "__NATIVE_ORIGIN__";
  if (location.origin !== origin) return;
  const bridge = globalThis.sovagridRestoreChannel || globalThis.webkit?.messageHandlers?.sovagridRestoreChannel;
  if (!bridge || typeof bridge.postMessage !== "function") return;
  if (globalThis.sovagridNativeRestore &&
      (typeof globalThis.__sovagridRestoreDispose !== "function" || !globalThis.__sovagridRestoreDispose(session))) return;
  const pending = new Map();
  let generation = 0, picking = false, disposed = false, queue = Promise.resolve();
  const random = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2,"0")).join("");
  const failure = message => new Error(message || "Скопируйте файлы копии на устройство и выберите их снова.");
  function invalidate() {
    generation++;
    for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(failure("Выбор файлов закрыт.")); }
    pending.clear();
  }
  globalThis.__sovagridRestoreReply = (replySession, id, value) => {
    if (replySession !== session) return;
    const entry = pending.get(id);
    if (!entry) return;
    pending.delete(id); clearTimeout(entry.timer);
    if (value && value.ok === true) entry.resolve(value); else entry.reject(failure(value?.error));
  };
  function send(action, fields = {}, timeout = 120000) {
    return new Promise((resolve, reject) => {
      const id = random();
      const timer = setTimeout(() => {
        pending.delete(id); reject(failure("Выбор файлов не ответил вовремя."));
        bridge.postMessage(JSON.stringify({action:"release",session,id:random()}));
        invalidate();
      }, timeout);
      pending.set(id, {resolve,reject,timer});
      try { bridge.postMessage(JSON.stringify({action,session,id,...fields})); }
      catch (error) { pending.delete(id); clearTimeout(timer); reject(error); }
    });
  }
  function fileLike(item, selectedGeneration) {
    if (!item || typeof item.name !== "string" || !item.name || /[\\/:\u0000-\u001f\u007f]/.test(item.name) ||
        !Number.isSafeInteger(item.size) || item.size < 1 || item.size > 8 * 1024**3 ||
        typeof item.handle !== "string" || !/^[a-f0-9]{64}$/.test(item.handle)) throw failure();
    function slice(start = 0, end = item.size) {
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start ||
          end > item.size || end - start > 4 * 1024**2) throw new RangeError("Можно читать фрагменты до 4 МБ.");
      return Object.freeze({size:end-start, arrayBuffer() {
        const task = queue.then(async () => {
          if (generation !== selectedGeneration) throw failure("Выбор файлов уже закрыт.");
          const result = new Uint8Array(end-start);
          for (let position = start; position < end; position += 262144) {
            if (generation !== selectedGeneration) throw failure("Выбор файлов уже закрыт.");
            const length = Math.min(262144,end-position);
            const value = await send("read",{handle:item.handle,offset:position,length},30000);
            if (generation !== selectedGeneration || typeof value.data !== "string" || value.data.length > 349528)
              throw failure("Передача файла прервана.");
            let bytes;
            try { bytes = atob(value.data); } catch { throw failure(); }
            if (bytes.length !== length) throw failure("Файл изменился или прочитан не полностью.");
            for (let index = 0; index < bytes.length; index++) result[position-start+index] = bytes.charCodeAt(index);
          }
          return result.buffer;
        });
        queue = task.catch(() => {});
        return task;
      }});
    }
    return Object.freeze({name:item.name,size:item.size,type:"application/octet-stream",slice,
      async text() {
        if (item.size > 65536) throw new RangeError("Текстовый манифест превышает 64 КиБ.");
        return new TextDecoder("utf-8",{fatal:true}).decode(await slice(0,item.size).arrayBuffer());
      }});
  }
  const api = Object.freeze({
    async pickFiles() {
      if (disposed) throw failure("Страница изменилась. Откройте выбор файлов снова.");
      if (picking) throw failure("Выбор файлов уже открыт.");
      picking = true; invalidate();
      const selectedGeneration = generation;
      try {
        const value = await send("pick");
        if (generation !== selectedGeneration || !Array.isArray(value.files) || value.files.length < 1 || value.files.length > 5)
          throw failure();
        let total = 0;
        const handles = new Set();
        const files = value.files.map(item => {
          const file = fileLike(item,selectedGeneration); total += file.size;
          if (handles.has(item.handle) || total > 16 * 1024**3) throw failure();
          handles.add(item.handle); return file;
        });
        return files;
      } catch (error) {
        bridge.postMessage(JSON.stringify({action:"release",session,id:random()}));
        invalidate(); throw error;
      } finally { picking = false; }
    },
    async release() { invalidate(); if (!disposed) await send("release"); }
  });
  function dispose() {
    if (disposed) return;
    disposed = true; invalidate();
    removeEventListener("pagehide",dispose);
    try { bridge.postMessage(JSON.stringify({action:"release",session,id:random()})); } catch {}
  }
  Object.defineProperty(globalThis,"sovagridNativeRestore",{value:api,writable:false,configurable:true});
  Object.defineProperty(globalThis,"__sovagridRestoreDispose",{value:nextSession => {
    if (nextSession === session && !disposed) return false;
    dispose(); return true;
  },writable:false,configurable:true});
  addEventListener("pagehide",dispose,{once:true});
  dispatchEvent(new Event("sovagrid-native-restore-ready"));
})();
"""
}
