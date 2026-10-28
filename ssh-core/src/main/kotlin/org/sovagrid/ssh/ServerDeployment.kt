/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import java.nio.charset.StandardCharsets

/** Read-only preflight over an already authenticated, pinned SSH connection. */
enum class ServerDeployment {
    MANAGED, AGENT_ONLY, MISSING, CONFLICT, UNSUPPORTED, UNKNOWN;

    companion object {
        private const val PREFIX = "SG_STATUS_V1:"
        const val MAX_OUTPUT_BYTES = 64

        fun parse(output: ByteArray, count: Int, exitStatus: Int?): ServerDeployment {
            if (exitStatus != 0 || count !in 1..MAX_OUTPUT_BYTES || count > output.size) return UNKNOWN
            val value = String(output, 0, count, StandardCharsets.US_ASCII)
                .removeSuffix("\n")
            if (!value.startsWith(PREFIX) || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) return UNKNOWN
            return when (value.removePrefix(PREFIX)) {
                "managed" -> MANAGED
                "agent_only" -> AGENT_ONLY
                "missing" -> MISSING
                "conflict" -> CONFLICT
                "unsupported" -> UNSUPPORTED
                "unknown" -> UNKNOWN
                else -> UNKNOWN
            }
        }
    }
}

/** No profile input is inserted into this command. Only root or passwordless sudo can claim absence. */
object ServerDeploymentProbe {
    private val script = listOf(
        "set -u",
        "if [ ! -r /etc/os-release ] || ! grep -Eq '^ID=\"?ubuntu\"?\$' /etc/os-release; then printf 'SG_STATUS_V1:unsupported\\n'; exit 0; fi",
        "for p in /opt/sovagrid-src /opt/sovagrid-agent /opt/sovagrid-vpn /opt/sovagrid-agent-installer /etc/sovagrid /etc/sovagrid-hub /etc/sovagrid-agent-tunnel /etc/sovagrid-agent-tunnel-public /var/lib/sovagrid /var/lib/sovagrid-agent /var/lib/sovagrid-agent-enrollment /var/lib/sovagrid-hub-tunnels /var/lib/sovagrid-first-install; do",
        "  if [ -L \"\$p\" ]; then printf 'SG_STATUS_V1:conflict\\n'; exit 0; fi",
        "done",
        "if [ -d /opt/sovagrid-src ] && [ \"\$(stat -c %u /opt/sovagrid-src 2>/dev/null)\" = 0 ] &&",
        "   [ -f /opt/sovagrid-src/sovagrid-bundle.json ] && [ ! -L /opt/sovagrid-src/sovagrid-bundle.json ] &&",
        "   [ \"\$(stat -c %u /opt/sovagrid-src/sovagrid-bundle.json 2>/dev/null)\" = 0 ] &&",
        "   [ -f /var/lib/sovagrid/.managed-by-run-sh ] && [ ! -L /var/lib/sovagrid/.managed-by-run-sh ] &&",
        "   [ \"\$(stat -c %u /var/lib/sovagrid/.managed-by-run-sh 2>/dev/null)\" = 0 ]; then",
        "   printf 'SG_STATUS_V1:managed\\n'; exit 0; fi",
        "if [ -f /opt/sovagrid-agent-installer/source-manifest.json ] &&",
        "   [ -f /etc/systemd/system/sovagrid-agent.service ] &&",
        "   [ -d /var/lib/sovagrid-agent-enrollment ] &&",
        "   [ ! -e /opt/sovagrid-src ] && [ ! -e /etc/sovagrid-hub ] &&",
        "   [ ! -e /var/lib/sovagrid ] && [ ! -e /etc/sovagrid/.agent-unit-managed-by-run-sh ]; then",
        "   printf 'SG_STATUS_V1:agent_only\\n'; exit 0; fi",
        "for p in /opt/sovagrid-src /opt/sovagrid-agent /opt/sovagrid-vpn /opt/sovagrid-agent-installer /etc/sovagrid /etc/sovagrid-hub /etc/sovagrid-agent-tunnel /etc/sovagrid-agent-tunnel-public /var/lib/sovagrid /var/lib/sovagrid-agent /var/lib/sovagrid-agent-enrollment /var/lib/sovagrid-hub-tunnels /var/lib/sovagrid-first-install; do",
        "   if [ -e \"\$p\" ]; then printf 'SG_STATUS_V1:conflict\\n'; exit 0; fi",
        "done",
        "for base in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system; do",
        "   for p in \"\$base\"/sovagrid-*; do",
        "      if [ -e \"\$p\" ] || [ -L \"\$p\" ]; then printf 'SG_STATUS_V1:conflict\\n'; exit 0; fi",
        "   done",
        "done",
        "if command -v docker >/dev/null 2>&1; then",
        "   if ! command -v timeout >/dev/null 2>&1; then printf 'SG_STATUS_V1:unknown\\n'; exit 0; fi",
        "   projects=\$(timeout 4 docker ps -a --filter label=com.docker.compose.project=sovagrid --format '{{.ID}}' 2>/dev/null) || { printf 'SG_STATUS_V1:unknown\\n'; exit 0; }",
        "   if [ -n \"\$projects\" ]; then printf 'SG_STATUS_V1:conflict\\n'; exit 0; fi",
        "fi",
        "printf 'SG_STATUS_V1:missing\\n'"
    ).joinToString("\n")

    private val quotedScript = "'" + script.replace("'", "'\\''") + "'"

    val READ_COMMAND = "if [ \"\$(id -u)\" = 0 ]; then /bin/sh -c $quotedScript; " +
        "elif command -v sudo >/dev/null 2>&1; then " +
        "sudo -n /bin/sh -c $quotedScript 2>/dev/null || printf 'SG_STATUS_V1:unknown\\n'; " +
        "else printf 'SG_STATUS_V1:unknown\\n'; fi"
}
