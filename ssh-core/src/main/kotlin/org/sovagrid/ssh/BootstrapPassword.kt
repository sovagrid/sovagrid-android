/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import java.io.IOException

/** Only the installer-generated URL-safe password is accepted from the fixed SSH command. */
object BootstrapPassword {
    const val READ_COMMAND = "head -c 257 /etc/sovagrid/admin-password"

    fun parse(output: ByteArray, length: Int = output.size): CharArray {
        if (length !in 0..output.size) throw IOException("Unexpected initial password format")
        var end = length
        if (end > 0 && output[end - 1] == '\n'.code.toByte()) {
            end--
            if (end > 0 && output[end - 1] == '\r'.code.toByte()) end--
        }
        if (end !in 20..128) throw IOException("Unexpected initial password format")
        for (index in 0 until end) {
            val code = output[index].toInt() and 0xff
            if (code !in 'A'.code..'Z'.code && code !in 'a'.code..'z'.code &&
                code !in '0'.code..'9'.code && code != '-'.code && code != '_'.code
            ) throw IOException("Unexpected initial password format")
        }
        return CharArray(end) { index -> (output[index].toInt() and 0xff).toChar() }
    }
}
