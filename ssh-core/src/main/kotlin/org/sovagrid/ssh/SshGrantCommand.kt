/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

/** A one-shot local Hub container issues the grant; arbitrary HTTP clients cannot mint one. */
object SshGrantCommand {
    const val MAX_RESPONSE_BYTES = 512

    private const val ISSUE = "docker compose --env-file /etc/sovagrid/deploy.env " +
        "-f /opt/sovagrid-src/sovagrid-blueprint/deploy/compose.yaml " +
        "run --rm --no-deps -T --entrypoint python3 hub " +
        "-m sovagrid_hub --db /data/hub.sqlite ssh-grant"

    val READ_COMMAND = "if [ \"\$(id -u)\" = 0 ]; then $ISSUE; " +
        "elif command -v sudo >/dev/null 2>&1; then sudo -n $ISSUE; " +
        "else exit 1; fi"
}
