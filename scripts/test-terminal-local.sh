#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sovagrid-terminal.XXXXXX")"
sshd_pid=''
cleanup() {
  if [[ -n "$sshd_pid" ]]; then
    kill "$sshd_pid" 2>/dev/null || true
    wait "$sshd_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_dir"
}
trap cleanup EXIT

port="$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    print(listener.getsockname()[1])
PY
)"
ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/host" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/user" >/dev/null
cp "$fixture_dir/user.pub" "$fixture_dir/authorized"
chmod 600 "$fixture_dir/authorized"
cat > "$fixture_dir/sshd.conf" <<EOF
ListenAddress 127.0.0.1
Port $port
HostKey $fixture_dir/host
AuthorizedKeysFile $fixture_dir/authorized
PidFile $fixture_dir/sshd.pid
AllowUsers $(id -un)
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitTTY yes
UsePAM no
StrictModes yes
LogLevel ERROR
EOF
/usr/sbin/sshd -t -f "$fixture_dir/sshd.conf"
/usr/sbin/sshd -D -f "$fixture_dir/sshd.conf" -E "$fixture_dir/sshd.log" &
sshd_pid=$!
for _ in {1..50}; do
  if python3 - "$port" 2>/dev/null <<'PY'
import socket, sys
with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=.2):
    pass
PY
  then break; fi
  sleep .1
done
export SOVAGRID_TEST_PTY_SSH_HOST=127.0.0.1
export SOVAGRID_TEST_PTY_SSH_PORT="$port"
export SOVAGRID_TEST_PTY_SSH_USER="$(id -un)"
export SOVAGRID_TEST_PTY_SSH_KEY_PATH="$fixture_dir/user"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
cd "$repo_dir"
./gradlew :ssh-core:test --tests org.sovagrid.ssh.TerminalPtyIntegrationTest --rerun-tasks --offline
