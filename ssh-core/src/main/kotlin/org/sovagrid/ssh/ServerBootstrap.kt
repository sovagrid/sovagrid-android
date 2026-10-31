/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import java.nio.charset.StandardCharsets

enum class FirstInstallState { NONE, RUNNING, DONE, FAILED, UNKNOWN }
data class FirstInstallJob(val state: FirstInstallState, val stage: String = "", val reason: String = "")

/** A fixed, detached root job survives phone backgrounding and can be reattached read-only. */
object ServerBootstrap {
    const val VERSION = "0.11.0"
    const val EXPECTED_SOURCE_SHA256 = "10abb18ca39d789d3a9cc8bd04d36126f6dd624a81e48219bd814fb6a15ab766"
    const val EXPECTED_MANIFEST_SHA256 = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
    private const val BUNDLE_URL = "https://github.com/sovagrid/sovagrid-blueprint/releases/download/server-v0.11.0/SovaGrid-server-source.tar.gz"
    const val MAX_OUTPUT_BYTES = 160
    private val stages = setOf("START", "DOWNLOAD", "VERIFY", "EXTRACT", "RUN", "CHECK")
    private val reasons = setOf("ROOT", "UBUNTU", "EXISTING", "UNKNOWN", "DOWNLOAD", "DOWNLOAD_TOOL", "HASH", "ARCHIVE", "LAYOUT", "STAGE", "RUN", "RESULT", "INTERRUPTED")
    private val jobScript = listOf(
        "set -Eeuo pipefail",
        "umask 077",
        "job_dir=/var/lib/sovagrid-first-install",
        "stage_code=START",
        "reason=INTERRUPTED",
        "state=running",
        "write_status() {",
        "  local temporary",
        "  temporary=\$(mktemp \"\$job_dir/.status.XXXXXXXX\") || return 1",
        "  printf 'SG_INSTALL_JOB_V1:%s:%s:%s\\n' \"\$1\" \"\$2\" \"\$3\" > \"\$temporary\"",
        "  chmod 0600 \"\$temporary\"",
        "  mv -f -- \"\$temporary\" \"\$job_dir/status\"",
        "}",
        "refuse() {",
        "  reason=\$1",
        "  if [[ -d \$job_dir && ! -L \$job_dir ]]; then write_status failed \"\$stage_code\" \"\$reason\" || true; fi",
        "  exit 30",
        "}",
        "status_stage() {",
        "  stage_code=\$1",
        "  write_status running \"\$stage_code\" NONE || exit 31",
        "}",
        "finish_status() {",
        "  if [[ \$state != done && -d \$job_dir && ! -L \$job_dir ]]; then",
        "    write_status failed \"\$stage_code\" \"\$reason\" || true",
        "  fi",
        "}",
        "check_empty() {",
        "  [[ \$(id -u) == 0 ]] || refuse ROOT",
        "  [[ -r /etc/os-release ]] || refuse UBUNTU",
        "  . /etc/os-release",
        "  [[ \${ID:-} == ubuntu ]] || refuse UBUNTU",
        "  for path in /opt/sovagrid-src /opt/sovagrid-agent /opt/sovagrid-vpn /opt/sovagrid-agent-installer /etc/sovagrid /etc/sovagrid-hub /etc/sovagrid-agent-tunnel /etc/sovagrid-agent-tunnel-public /var/lib/sovagrid /var/lib/sovagrid-agent /var/lib/sovagrid-agent-enrollment /var/lib/sovagrid-hub-tunnels; do",
        "    [[ ! -e \$path && ! -L \$path ]] || refuse EXISTING",
        "  done",
        "  for base in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system; do",
        "    for path in \"\$base\"/sovagrid-*; do",
        "      [[ \$path == */sovagrid-first-install.service ]] && continue",
        "      [[ ! -e \$path && ! -L \$path ]] || refuse EXISTING",
        "    done",
        "  done",
        "  if command -v docker >/dev/null 2>&1; then",
        "    command -v timeout >/dev/null 2>&1 || refuse UNKNOWN",
        "    projects=\$(timeout 4 docker ps -a --filter label=com.docker.compose.project=sovagrid --format '{{.ID}}' 2>/dev/null) || refuse UNKNOWN",
        "    [[ -z \$projects ]] || refuse EXISTING",
        "  fi",
        "}",
        "[[ ! -L /run/sovagrid-first-install.lock ]] || exit 32",
        "exec 9>/run/sovagrid-first-install.lock",
        "flock -n 9 || exit 33",
        "check_empty",
        "[[ ! -e \$job_dir && ! -L \$job_dir ]] || exit 34",
        "mkdir -m 0700 -- \"\$job_dir\" || exit 35",
        "trap finish_status EXIT",
        "status_stage START",
        "archive=\$(mktemp /opt/.sovagrid-mobile-bundle.XXXXXXXX) || refuse STAGE",
        "stage_dir=\$(mktemp -d /opt/.sovagrid-mobile-stage.XXXXXXXX) || { rm -f -- \"\$archive\"; refuse STAGE; }",
        "cleanup() { rm -f -- \"\$archive\"; if [[ -d \$stage_dir ]]; then rm -rf -- \"\$stage_dir\"; fi; }",
        "trap 'cleanup || true; finish_status' EXIT",
        "url='$BUNDLE_URL'",
        "expected='$EXPECTED_SOURCE_SHA256'",
        "manifest='$EXPECTED_MANIFEST_SHA256'",
        "status_stage DOWNLOAD",
        "if command -v curl >/dev/null 2>&1; then",
        "  curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --max-filesize 67108864 --output \"\$archive\" \"\$url\" >/dev/null 2>&1 || refuse DOWNLOAD",
        "elif command -v wget >/dev/null 2>&1; then",
        "  timeout 180 bash -o pipefail -c 'wget --quiet --https-only --output-document=- \"\$1\" | head -c 67108865 > \"\$2\"' sovagrid \"\$url\" \"\$archive\" >/dev/null 2>&1 || refuse DOWNLOAD",
        "elif command -v python3 >/dev/null 2>&1; then",
        "  python3 - \"\$archive\" <<'PY' >/dev/null 2>&1 || refuse DOWNLOAD",
        "import sys",
        "import urllib.request",
        "url = '$BUNDLE_URL'",
        "with urllib.request.urlopen(url, timeout=30) as source, open(sys.argv[1], 'wb') as target:",
        "    if not source.url.startswith('https://'):",
        "        raise SystemExit(1)",
        "    total = 0",
        "    while True:",
        "        block = source.read(65536)",
        "        if not block:",
        "            break",
        "        total += len(block)",
        "        if total > 67108864:",
        "            raise SystemExit(1)",
        "        target.write(block)",
        "PY",
        "else",
        "  refuse DOWNLOAD_TOOL",
        "fi",
        "status_stage VERIFY",
        "[[ -s \$archive && \$(stat -c %s \"\$archive\") -le 67108864 ]] || refuse HASH",
        "[[ \$(sha256sum \"\$archive\" | cut -d' ' -f1) == \"\$expected\" ]] || refuse HASH",
        "check_empty",
        "tar --no-same-owner --same-permissions -xzf \"\$archive\" -C \"\$stage_dir\" >/dev/null 2>&1 || refuse ARCHIVE",
        "status_stage EXTRACT",
        "for component in sovagrid-blueprint sovagrid-hub sovagrid-web sovagrid-agent sovagrid-vpn; do",
        "  [[ -d \$stage_dir/\$component && ! -L \$stage_dir/\$component ]] || refuse LAYOUT",
        "done",
        "for required in sovagrid-blueprint/run.sh sovagrid-blueprint/deploy/compose.yaml sovagrid-hub/Dockerfile sovagrid-web/Dockerfile sovagrid-web/deploy/Caddyfile.container sovagrid-agent/deploy/sovagrid-agent.service sovagrid-vpn/deploy/sovagrid-vpn-status.service sovagrid-bundle.json; do",
        "  [[ -f \$stage_dir/\$required && ! -L \$stage_dir/\$required ]] || refuse LAYOUT",
        "done",
        "[[ \$(find \"\$stage_dir\" -mindepth 1 -maxdepth 1 -print | wc -l) -eq 6 ]] || refuse LAYOUT",
        "[[ -z \$(find \"\$stage_dir\" ! -type f ! -type d -print -quit) ]] || refuse LAYOUT",
        "[[ -z \$(find \"\$stage_dir\" -mindepth 1 -type d ! -perm 0755 -print -quit) ]] || refuse LAYOUT",
        "[[ -z \$(find \"\$stage_dir\" -type f ! -perm 0644 ! -perm 0755 -print -quit) ]] || refuse LAYOUT",
        "[[ \$(sha256sum \"\$stage_dir/sovagrid-bundle.json\" | cut -d' ' -f1) == \"\$manifest\" ]] || refuse HASH",
        "check_empty",
        "mv -T -- \"\$stage_dir\" /opt/sovagrid-src || refuse STAGE",
        "status_stage RUN",
        "bash /opt/sovagrid-src/sovagrid-blueprint/run.sh > \"\$job_dir/install.log\" 2>&1 || refuse RUN",
        "status_stage CHECK",
        "[[ -f /var/lib/sovagrid/.managed-by-run-sh && ! -L /var/lib/sovagrid/.managed-by-run-sh ]] || refuse RESULT",
        "[[ \$(sha256sum /opt/sovagrid-src/sovagrid-bundle.json | cut -d' ' -f1) == \"\$manifest\" ]] || refuse HASH",
        "systemctl is-active --quiet sovagrid-agent.service || refuse RESULT",
        "python3 -c 'import urllib.request; r=urllib.request.urlopen(\"http://127.0.0.1:8766/healthz\", timeout=5); assert r.status == 200; r.close()' >/dev/null 2>&1 || refuse RESULT",
        "write_status done DONE NONE || exit 36",
        "state=done",
    ).joinToString("\n")
    private val statusScript = listOf(
        "set -eu",
        "job_dir=/var/lib/sovagrid-first-install",
        "unit=sovagrid-first-install.service",
        "active() {",
        "  unit_state=\$(systemctl is-active \"\$unit\" 2>/dev/null || true)",
        "  [ \"\$unit_state\" = active ] || [ \"\$unit_state\" = activating ]",
        "}",
        "if [ ! -e \"\$job_dir\" ] && [ ! -L \"\$job_dir\" ]; then",
        "  if active; then printf 'SG_INSTALL_JOB_V1:running:START:NONE\\n';",
        "  else printf 'SG_INSTALL_JOB_V1:none\\n'; fi",
        "  exit 0",
        "fi",
        "if [ -L \"\$job_dir\" ] || [ ! -d \"\$job_dir\" ] ||",
        "   [ \"\$(stat -c '%u:%a' \"\$job_dir\" 2>/dev/null)\" != '0:700' ]; then",
        "  printf 'SG_INSTALL_JOB_V1:unknown\\n'; exit 0",
        "fi",
        "status=\"\$job_dir/status\"",
        "if [ ! -e \"\$status\" ] && [ ! -L \"\$status\" ]; then",
        "  if active; then printf 'SG_INSTALL_JOB_V1:running:START:NONE\\n';",
        "  else printf 'SG_INSTALL_JOB_V1:failed:START:INTERRUPTED\\n'; fi",
        "  exit 0",
        "fi",
        "if [ -L \"\$status\" ] || [ ! -f \"\$status\" ] ||",
        "   [ \"\$(stat -c '%u:%a:%h' \"\$status\" 2>/dev/null)\" != '0:600:1' ] ||",
        "   [ \"\$(stat -c %s \"\$status\" 2>/dev/null)\" -gt 128 ]; then",
        "  printf 'SG_INSTALL_JOB_V1:unknown\\n'; exit 0",
        "fi",
        "value=\$(cat \"\$status\") || { printf 'SG_INSTALL_JOB_V1:unknown\\n'; exit 0; }",
        "case \"\$value\" in",
        "  SG_INSTALL_JOB_V1:running:START:NONE|SG_INSTALL_JOB_V1:running:DOWNLOAD:NONE|SG_INSTALL_JOB_V1:running:VERIFY:NONE|SG_INSTALL_JOB_V1:running:EXTRACT:NONE|SG_INSTALL_JOB_V1:running:RUN:NONE|SG_INSTALL_JOB_V1:running:CHECK:NONE)",
        "    if active; then printf '%s\\n' \"\$value\";",
        "    else printf 'SG_INSTALL_JOB_V1:failed:START:INTERRUPTED\\n'; fi ;;",
        "  SG_INSTALL_JOB_V1:done:DONE:NONE) printf '%s\\n' \"\$value\" ;;",
        "  SG_INSTALL_JOB_V1:failed:*)",
        "    case \"\$value\" in",
        "      *:ROOT|*:UBUNTU|*:EXISTING|*:UNKNOWN|*:DOWNLOAD|*:DOWNLOAD_TOOL|*:HASH|*:ARCHIVE|*:LAYOUT|*:STAGE|*:RUN|*:RESULT|*:INTERRUPTED) printf '%s\\n' \"\$value\" ;;",
        "      *) printf 'SG_INSTALL_JOB_V1:unknown\\n' ;;",
        "    esac ;;",
        "  *) printf 'SG_INSTALL_JOB_V1:unknown\\n' ;;",
        "esac",
    ).joinToString("\n")
    private fun shellQuote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    /** systemd owns the install after this SSH command returns. No profile data is interpolated. */
    val START_COMMAND: String = "if [ \"\$(id -u)\" != 0 ]; then exit 1; fi; " +
        "if [ -e /var/lib/sovagrid-first-install ] || [ -L /var/lib/sovagrid-first-install ]; then exit 2; fi; " +
        "systemd-run --quiet --collect --unit=sovagrid-first-install " +
        "--property=Type=exec --property=RuntimeMaxSec=2700 " +
        "--property=StandardOutput=null --property=StandardError=null " +
        "/bin/bash -c " + shellQuote(jobScript) + " >/dev/null 2>&1 || exit 3; " +
        "printf 'SG_INSTALL_START_V1:OK\\n'"

    val STATUS_COMMAND: String = "if [ \"\$(id -u)\" = 0 ]; then /bin/sh -c " + shellQuote(statusScript) +
        "; elif command -v sudo >/dev/null 2>&1; then sudo -n /bin/sh -c " + shellQuote(statusScript) +
        " 2>/dev/null || printf 'SG_INSTALL_JOB_V1:unknown\\n'; " +
        "else printf 'SG_INSTALL_JOB_V1:unknown\\n'; fi"

    fun parseStatus(output: ByteArray, count: Int, exitStatus: Int?): FirstInstallJob {
        if (exitStatus != 0 || count !in 1..MAX_OUTPUT_BYTES || count > output.size) return FirstInstallJob(FirstInstallState.UNKNOWN)
        val value = String(output, 0, count, StandardCharsets.US_ASCII)
        if (!value.endsWith("\n")) return FirstInstallJob(FirstInstallState.UNKNOWN)
        val line = value.dropLast(1)
        if (line.contains('\n') || line.contains('\r') || !line.startsWith("SG_INSTALL_JOB_V1:")) return FirstInstallJob(FirstInstallState.UNKNOWN)
        val parts = line.split(':')
        return when {
            parts == listOf("SG_INSTALL_JOB_V1", "none") -> FirstInstallJob(FirstInstallState.NONE)
            parts == listOf("SG_INSTALL_JOB_V1", "unknown") -> FirstInstallJob(FirstInstallState.UNKNOWN)
            parts == listOf("SG_INSTALL_JOB_V1", "done", "DONE", "NONE") -> FirstInstallJob(FirstInstallState.DONE, "DONE")
            parts.size == 4 && parts[0] == "SG_INSTALL_JOB_V1" && parts[1] == "running" &&
                parts[2] in stages && parts[3] == "NONE" -> FirstInstallJob(FirstInstallState.RUNNING, parts[2])
            parts.size == 4 && parts[0] == "SG_INSTALL_JOB_V1" && parts[1] == "failed" &&
                parts[2] in stages && parts[3] in reasons -> FirstInstallJob(FirstInstallState.FAILED, parts[2], parts[3])
            else -> FirstInstallJob(FirstInstallState.UNKNOWN)
        }
    }

    fun stageText(stage: String): String = when (stage) {
        "START" -> "Установка запускается на сервере…"
        "DOWNLOAD" -> "Сервер загружает проверенный пакет…"
        "VERIFY" -> "Проверяем SHA-256 пакета…"
        "EXTRACT" -> "Распаковываем серверную часть…"
        "RUN" -> "Устанавливаем Hub и Agent…"
        "CHECK" -> "Проверяем работу панели и Agent…"
        else -> "Проверяем состояние установки…"
    }

    fun failureText(reason: String): String = when (reason) {
        "ROOT" -> "Для первой установки нужен вход root по SSH."
        "UBUNTU" -> "Первая установка поддерживает Ubuntu."
        "EXISTING" -> "На сервере уже есть SovaGrid или заняты его служебные пути."
        "DOWNLOAD", "DOWNLOAD_TOOL" -> "Сервер не смог загрузить пакет. Проверьте доступ к GitHub."
        "HASH" -> "Пакет или манифест не совпали с проверенным SHA-256."
        "ARCHIVE", "LAYOUT" -> "Сервер отклонил структуру пакета."
        "RUN", "RESULT" -> "Установка началась, но Hub не прошёл проверку. Проверьте сервер перед повторением."
        else -> "Установка прервалась. Проверьте сервер перед повторением."
    }
}
