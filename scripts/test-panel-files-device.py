#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Actual panel HTTP/Blob download + system picker upload on a disposable AVD.

Requires an already booted AVD whose name begins SovaGridPanelFiles, debug and
androidTest APKs, macOS sshd/ssh-keygen, and free loopback ports 8766/22224.
No physical device, user AVD or external server is accepted.
"""
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
from panel_files_http_fixture import Handler, PAYLOAD

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", type=Path, default=Path.home()/"Library/Android/sdk/platform-tools/adb")
    parser.add_argument("--diagnostics-dir", type=Path)
    args = parser.parse_args()
    def adb(*parts):
        return subprocess.check_output([str(args.adb), "-s", args.serial, *parts], text=True,
                                       stderr=subprocess.STDOUT, timeout=180)
    assert adb("shell", "getprop", "ro.kernel.qemu").strip() == "1", "Disposable emulator required"
    assert adb("emu", "avd", "name").splitlines()[0].startswith("SovaGridPanelFiles"), "Refusing a user AVD"
    # An interrupted picker can outlive its calling test activity. This AVD is
    # disposable: close only its picker/fixture app before creating fresh keys.
    for package in ("com.android.documentsui", "com.google.android.documentsui", "org.sovagrid.android"):
        adb("shell", "am", "force-stop", package)
    # This is a fresh, explicitly disposable AVD. Reset only its synthetic
    # download provider to avoid stale rows after a previously interrupted run.
    adb("shell", "pm", "clear", "com.android.providers.downloads")
    adb("shell", "rm", "-f", "/sdcard/Download/panel-native.bin", "/sdcard/Download/panel-blob.bin")
    packages = adb("shell", "pm", "list", "packages", "org.sovagrid.android").splitlines()
    if "package:org.sovagrid.android" in packages:
        adb("shell", "pm", "clear", "org.sovagrid.android")
    username = getpass.getuser()
    with tempfile.TemporaryDirectory(prefix="sovagrid-android-panel-files-") as temporary:
        folder = Path(temporary)
        folder.chmod(0o700)
        host_key = folder/"host-key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
        pin = host_key.with_suffix(".pub").read_text().split()[1]
        authorized = folder/"authorized"
        authorized.write_text(""); authorized.chmod(0o600)
        command = folder/"probe.sh"
        command.write_text("#!/bin/sh\nprintf 'SYNTHETIC_PANEL_FIXTURE\\n'\n"); command.chmod(0o700)
        config = folder/"sshd.conf"
        config.write_text("\n".join([
            "Port 22224", "ListenAddress 127.0.0.1", f"HostKey {host_key}",
            f"AuthorizedKeysFile {authorized}", "PasswordAuthentication no", "PubkeyAuthentication yes",
            "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no", f"AllowUsers {username}",
            "AllowTcpForwarding yes", "PermitOpen 127.0.0.1:8766", f"PidFile {folder/'sshd.pid'}",
            f"ForceCommand /bin/sh {command}", "LogLevel ERROR", ""]))
        Handler.output_directory = folder
        Handler.download_count = 0
        server = http.server.ThreadingHTTPServer(("127.0.0.1",8766),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        ssh = None
        with (folder/"ssh.log").open("w") as log:
            try:
                ssh = subprocess.Popen(["/usr/sbin/sshd","-D","-e","-f",str(config)],stdout=log,stderr=subprocess.STDOUT)
                time.sleep(0.3); assert ssh.poll() is None, "Local fixture sshd failed"
                for apk in [ROOT/"app/build/outputs/apk/debug/app-debug.apk",ROOT/"app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"]:
                    print(adb("install","-r",str(apk)).strip(),flush=True)
                runner="org.sovagrid.android.test/org.sovagrid.android.SshKeyVaultInstrumentation"
                prepared=adb("shell","am","instrument","-w","-e","mode","panel-files-setup",
                             "-e","username",username,"-e","pin",pin,runner)
                match=re.search(r"public_key=(ssh-ed25519 [A-Za-z0-9+/=]+)",prepared)
                assert match is not None and "INSTRUMENTATION_CODE: -1" in prepared, "Fixture setup failed: "+prepared
                authorized.write_text(match.group(1)+"\n")
                result=adb("shell","am","instrument","-w","-e","mode","panel-files-ui",runner)
                print(result,flush=True)
                assert "panel-files-ui passed" in result and "INSTRUMENTATION_CODE: -1" in result, "Native panel UI round-trip failed"
                upload=json.loads((folder/"native-upload-result.json").read_text())
                assert Handler.download_count == 1
                assert upload=={"filename":"panel-native.bin","bytes":len(PAYLOAD),"sha256":hashlib.sha256(PAYLOAD).hexdigest()}
                print("PASS actual Android SSH panel, authenticated HTTP + Blob saves, and private-provider upload",flush=True)
            except Exception:
                for diagnostic in ("native-browser-events.json", "native-bridge-events.json"):
                    captured = folder/diagnostic
                    if captured.exists(): print(diagnostic, captured.read_text(), flush=True)
                if args.diagnostics_dir:
                    try:
                        screenshot = subprocess.check_output([str(args.adb), "-s", args.serial, "exec-out", "run-as",
                            "org.sovagrid.android", "cat", "cache/panel-picker-diagnostic.png"], timeout=10,
                            stderr=subprocess.DEVNULL)
                        args.diagnostics_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                        (args.diagnostics_dir/"panel-picker.png").write_bytes(screenshot)
                    except (OSError, subprocess.SubprocessError): pass
                raise
            finally:
                if ssh is not None:
                    ssh.terminate()
                    try: ssh.wait(timeout=5)
                    except subprocess.TimeoutExpired: ssh.kill();ssh.wait()
                server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=="__main__": main()
