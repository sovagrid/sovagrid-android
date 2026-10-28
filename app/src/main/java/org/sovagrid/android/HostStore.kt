/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.sovagrid.ssh.Endpoint
import java.util.UUID

data class SavedServer(
    val id: String,
    val label: String,
    val endpoint: Endpoint,
    val pinnedKey: String?,
    val jumpEndpoint: Endpoint? = null,
    val jumpPinnedKey: String? = null
)

/** Only server addresses and public host keys are persisted. No credentials are accepted here. */
class HostStore(context: Context) {
    private val preferences = context.getSharedPreferences("sovagrid_hosts", Context.MODE_PRIVATE)
    private val key = "servers_v1"

    fun all(): List<SavedServer> {
        val data = preferences.getString(key, "[]") ?: "[]"
        val array = JSONArray(data)
        return (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            val jump = item.optJSONObject("jump")
            SavedServer(
                id = item.getString("id"),
                label = item.getString("label"),
                endpoint = Endpoint(
                    item.getString("host"),
                    item.getInt("port"),
                    item.getString("username")
                ),
                pinnedKey = item.optString("pinnedKey").takeIf { it.isNotEmpty() },
                jumpEndpoint = jump?.let {
                    Endpoint(it.getString("host"), it.getInt("port"), it.getString("username"))
                },
                jumpPinnedKey = jump?.optString("pinnedKey")?.takeIf { it.isNotEmpty() }
            )
        }
    }

    fun add(label: String, endpoint: Endpoint, jumpEndpoint: Endpoint? = null): SavedServer {
        val server = SavedServer(UUID.randomUUID().toString(), label.trim(), endpoint, null, jumpEndpoint)
        save(all() + server)
        return server
    }

    fun remove(id: String) = save(all().filterNot { it.id == id })

    /** Public key IDs only: remember which profile/route explicitly selected a device key. */
    fun recordKeySelection(serverId: String, keyId: String?, gateway: Boolean = false): Boolean {
        if (all().none { it.id == serverId } || keyId != null && !SshKeyReference.validId(keyId)) return false
        val selections = JSONObject(preferences.getString("ssh_key_selections_v1", "{}") ?: "{}")
        val slot = "$serverId:${if (gateway) "gateway" else "target"}"
        if (keyId == null) selections.remove(slot) else selections.put(slot, keyId)
        return preferences.edit().putString("ssh_key_selections_v1", selections.toString()).commit()
    }

    fun keyUsages(keyId: String): List<String> {
        val selections = JSONObject(preferences.getString("ssh_key_selections_v1", "{}") ?: "{}")
        return all().flatMap { server -> listOfNotNull(
            "${server.label} · конечный сервер".takeIf { selections.optString("${server.id}:target") == keyId },
            "${server.label} · промежуточный узел".takeIf { selections.optString("${server.id}:gateway") == keyId }
        ) }
    }

    fun forgetKeySelections(keyId: String): Boolean {
        val selections = JSONObject(preferences.getString("ssh_key_selections_v1", "{}") ?: "{}")
        val keys = selections.keys().asSequence().toList()
        for (slot in keys) if (selections.optString(slot) == keyId) selections.remove(slot)
        return preferences.edit().putString("ssh_key_selections_v1", selections.toString()).commit()
    }

    fun pin(id: String, gateway: Boolean = false): String? = all().firstOrNull { it.id == id }?.let {
        if (gateway) it.jumpPinnedKey else it.pinnedKey
    }

    fun setPin(id: String, pinnedKey: String?, gateway: Boolean = false): Boolean {
        val hosts = all()
        if (hosts.none { it.id == id }) return false
        return save(hosts.map {
            if (it.id != id) it else if (gateway) it.copy(jumpPinnedKey = pinnedKey)
            else it.copy(pinnedKey = pinnedKey)
        })
    }

    private fun save(hosts: List<SavedServer>): Boolean {
        val array = JSONArray()
        hosts.forEach { server ->
            array.put(JSONObject().apply {
                put("id", server.id)
                put("label", server.label)
                put("host", server.endpoint.host)
                put("port", server.endpoint.port)
                put("username", server.endpoint.username)
                put("pinnedKey", server.pinnedKey ?: "")
                server.jumpEndpoint?.let { jump ->
                    put("jump", JSONObject().apply {
                        put("host", jump.host)
                        put("port", jump.port)
                        put("username", jump.username)
                        put("pinnedKey", server.jumpPinnedKey ?: "")
                    })
                }
            })
        }
        // commit() makes a newly approved pin durable before authentication starts.
        return preferences.edit().putString(key, array.toString()).commit()
    }
}
