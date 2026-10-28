#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/sovagrid-panel-jump.XXXXXX")"
gateway_pid=''
home_pid=''
http_pid=''
cleanup() {
  for pid in "$gateway_pid" "$home_pid" "$http_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$fixture_dir"
}
trap cleanup EXIT

user_name="$(id -un)"
read -r gateway_port home_port < <(python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        ports.append(listener.getsockname()[1])
print(*ports)
PY
)
mkdir -m 700 "$fixture_dir/keys" "$fixture_dir/www"
mkdir -p "$fixture_dir/www/sovagrid/monitoring"
printf 'SOVAGRID_HOME_PANEL_FIXTURE\n' > "$fixture_dir/www/sovagrid/monitoring/index.html"
for name in gateway_host home_host gateway_user home_user; do
  ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/keys/$name" >/dev/null
done
cp "$fixture_dir/keys/gateway_user.pub" "$fixture_dir/keys/gateway_authorized"
cp "$fixture_dir/keys/home_user.pub" "$fixture_dir/keys/home_authorized"
chmod 600 "$fixture_dir/keys/"*authorized

cat > "$fixture_dir/home-force.sh" <<'SH'
#!/bin/sh
printf 'FixturePassword_0123456789\n'
SH
chmod 700 "$fixture_dir/home-force.sh"
cat > "$fixture_dir/gateway-force.sh" <<'SH'
#!/bin/sh
printf 'VpsFixturePassword_0123456789\n'
SH
chmod 700 "$fixture_dir/gateway-force.sh"

for role in gateway home; do
  if [[ "$role" == gateway ]]; then
    port="$gateway_port"
    permit="127.0.0.1:$home_port 127.0.0.1:8766"
  else
    port="$home_port"
    permit='127.0.0.1:8766'
  fi
  cat > "$fixture_dir/$role.conf" <<EOF
ListenAddress 127.0.0.1
Port $port
HostKey $fixture_dir/keys/${role}_host
AuthorizedKeysFile $fixture_dir/keys/${role}_authorized
PidFile $fixture_dir/$role.pid
AllowUsers $user_name
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitOpen $permit
AllowTcpForwarding local
UsePAM no
StrictModes yes
LogLevel ERROR
EOF
  printf 'ForceCommand %s/%s-force.sh\n' "$fixture_dir" "$role" >> "$fixture_dir/$role.conf"
  /usr/sbin/sshd -t -f "$fixture_dir/$role.conf"
done

python3 -m http.server 8766 --bind 127.0.0.1 --directory "$fixture_dir/www" > "$fixture_dir/http.log" 2>&1 &
http_pid=$!
/usr/sbin/sshd -D -f "$fixture_dir/gateway.conf" -E "$fixture_dir/gateway.log" &
gateway_pid=$!
/usr/sbin/sshd -D -f "$fixture_dir/home.conf" -E "$fixture_dir/home.log" &
home_pid=$!

ready=''
for _ in {1..50}; do
  if kill -0 "$gateway_pid" "$home_pid" "$http_pid" 2>/dev/null &&
      python3 - "$gateway_port" "$home_port" 2>/dev/null <<'PY'
import socket, sys
for port in (8766, int(sys.argv[1]), int(sys.argv[2])):
    with socket.create_connection(('127.0.0.1', port), timeout=.2):
        pass
PY
  then ready=yes; break; fi
  sleep .1
done
if [[ "$ready" != yes ]] || [[ "$(curl -fsS --max-time 2 http://127.0.0.1:8766/sovagrid/monitoring/)" != *SOVAGRID_HOME_PANEL_FIXTURE* ]]; then
  echo 'Local SSH/HTTP fixture did not become ready' >&2
  exit 1
fi

export SOVAGRID_TEST_PANEL_GATEWAY_PORT="$gateway_port"
export SOVAGRID_TEST_PANEL_HOME_PORT="$home_port"
export SOVAGRID_TEST_PANEL_USER="$user_name"
export SOVAGRID_TEST_PANEL_GATEWAY_KEY_PATH="$fixture_dir/keys/gateway_user"
export SOVAGRID_TEST_PANEL_HOME_KEY_PATH="$fixture_dir/keys/home_user"
cd "$repo_dir"
./gradlew :ssh-core:test --tests org.sovagrid.ssh.PanelJumpIntegrationTest --rerun-tasks --offline
