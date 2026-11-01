#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real >4MiB restore picker + bounded FD slice/hash proof on a disposable AVD."""
import argparse
import getpass
import hashlib
import http.server
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
from panel_files_http_fixture import Handler

ROOT = Path(__file__).resolve().parents[1]
SIZE = 8 * 1024 * 1024 + 23
PAGE = b'''<!doctype html><meta name="viewport" content="width=device-width"><title>SovaGrid</title>
<style>body{font:18px sans-serif;padding:14px}button{font:18px sans-serif;margin:24px 0}</style>
<p>NATIVE RESTORE FIXTURE</p><p id="result">WAITING_NATIVE</p><button id="pick">Choose backup files</button>
<script>
const result=document.querySelector('#result');
function ready(){if(globalThis.sovagridNativeRestore)result.textContent='NATIVE_RESTORE_READY'}
addEventListener('sovagrid-native-restore-ready',ready);ready();
pick.onclick=async()=>{try{
 const files=await sovagridNativeRestore.pickFiles();if(files.length!==1)throw Error('count');
 const f=files[0], slices=[];let textRejected=false,oversizeRejected=false,staleRejected=false;
 try{await f.text()}catch{textRejected=true}
 try{f.slice(0,4194305)}catch{oversizeRejected=true}
 for(let offset=0;offset<f.size;offset+=4194304){const end=Math.min(f.size,offset+4194304);
  const bytes=await f.slice(offset,end).arrayBuffer();
  const sha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('');
  slices.push({offset,bytes:bytes.byteLength,sha256:sha});}
 await sovagridNativeRestore.release();try{await f.slice(0,1).arrayBuffer()}catch{staleRejected=true}
 const response=await fetch('/_fixture/restore-result',{method:'POST',body:JSON.stringify({name:f.name,size:f.size,slices,textRejected,oversizeRejected,staleRejected})});
 result.textContent=response.ok?'RESTORE_OK':'RESTORE_BAD_HASH';
}catch(e){result.textContent='RESTORE_ERROR '+e.message}};</script>'''


class RestoreHandler(Handler):
    def do_GET(self):
        if self.path in ("/sovagrid/monitoring/", "/sovagrid/monitoring/index.html"):
            return self.reply(200, PAGE, "text/html", cookie=True)
        return super().do_GET()

    def do_POST(self):
        if self.path != "/_fixture/restore-result":
            return super().do_POST()
        try:
            length = int(self.headers.get("Content-Length", "0"))
            assert 0 < length <= 4096
            value = json.loads(self.rfile.read(length))
            slices = []
            for offset in range(0, SIZE, 4 * 1024**2):
                count = min(4 * 1024**2, SIZE-offset)
                digest = hashlib.sha256(bytes((offset+i) % 251 for i in range(count))).hexdigest()
                slices.append({"offset": offset, "bytes": count, "sha256": digest})
            assert value == {"name": "panel-restore.bin", "size": SIZE, "slices": slices,
                             "textRejected": True, "oversizeRejected": True, "staleRejected": True}
            (self.output_directory / "native-restore-result.json").write_text(json.dumps(value))
        except Exception:
            return self.reply(400, b"invalid restore proof")
        return self.reply(200, b"ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", type=Path, default=Path.home()/"Library/Android/sdk/platform-tools/adb")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    def adb(*parts):
        return subprocess.check_output([str(args.adb), "-s", args.serial, *parts], text=True,
                                       stderr=subprocess.STDOUT, timeout=180)

    assert adb("shell", "getprop", "ro.kernel.qemu").strip() == "1"
    assert adb("emu", "avd", "name").splitlines()[0].startswith("SovaGridPanelRestore"), "Refusing a user AVD"
    for package in ("com.android.documentsui", "com.google.android.documentsui", "org.sovagrid.android"):
        adb("shell", "am", "force-stop", package)
    username = getpass.getuser()
    with tempfile.TemporaryDirectory(prefix="sovagrid-restore-panel-") as temporary:
        folder = Path(temporary); folder.chmod(0o700)
        host_key = folder/"host-key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
        pin = host_key.with_suffix(".pub").read_text().split()[1]
        authorized = folder/"authorized"; authorized.write_text(""); authorized.chmod(0o600)
        command = folder/"probe.sh"
        command.write_text("#!/bin/sh\nprintf 'SYNTHETIC_PANEL_FIXTURE\\n'\n"); command.chmod(0o700)
        config = folder/"sshd.conf"
        config.write_text("\n".join(["Port 22224", "ListenAddress 127.0.0.1", f"HostKey {host_key}",
            f"AuthorizedKeysFile {authorized}", "PasswordAuthentication no", "PubkeyAuthentication yes",
            "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no", f"AllowUsers {username}",
            "AllowTcpForwarding yes", "PermitOpen 127.0.0.1:8766", f"PidFile {folder/'sshd.pid'}",
            f"ForceCommand /bin/sh {command}", "LogLevel ERROR", ""]))
        RestoreHandler.output_directory = folder
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 8766), RestoreHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        ssh = None
        with (folder/"ssh.log").open("w") as log:
            try:
                ssh = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=subprocess.STDOUT)
                time.sleep(0.3); assert ssh.poll() is None
                for apk in (ROOT/"app/build/outputs/apk/debug/app-debug.apk",
                            ROOT/"app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"):
                    print(adb("install", "-r", str(apk)).strip(), flush=True)
                adb("shell", "pm", "clear", "org.sovagrid.android")
                runner = "org.sovagrid.android.test/org.sovagrid.android.SshKeyVaultInstrumentation"
                setup = adb("shell", "am", "instrument", "-w", "-e", "mode", "panel-files-setup",
                            "-e", "username", username, "-e", "pin", pin, runner)
                match = re.search(r"public_key=(ssh-ed25519 [A-Za-z0-9+/=]+)", setup)
                assert match is not None and "INSTRUMENTATION_CODE: -1" in setup, setup
                authorized.write_text(match.group(1) + "\n")
                result = adb("shell", "am", "instrument", "-w", "-e", "mode", "panel-restore-ui", runner)
                print(result, flush=True)
                assert "panel-restore-ui passed" in result and "INSTRUMENTATION_CODE: -1" in result
                proof = json.loads((folder/"native-restore-result.json").read_text())
                if args.report:
                    args.report.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    args.report.write_text(json.dumps(proof, indent=2) + "\n")
                print("PASS actual >4MiB native picker, bounded slice hashes, mutation/range checks and release", flush=True)
            finally:
                if ssh is not None:
                    ssh.terminate()
                    try: ssh.wait(timeout=5)
                    except subprocess.TimeoutExpired: ssh.kill(); ssh.wait()
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    main()
