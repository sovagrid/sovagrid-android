/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.android

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/** Read-only app-private snapshots for WebView file inputs; no broad storage permission. */
class PanelUploadProvider : ContentProvider() {
    override fun onCreate() = true
    private fun file(uri: Uri): File {
        val parts = uri.pathSegments
        if (uri.query != null || uri.fragment != null || parts.size != 2 ||
            !Regex("[0-9a-f]{32}").matches(parts[0]) || !PanelFileContract.safeFilename(parts[1]))
            throw FileNotFoundException()
        val base = File(requireNotNull(context).cacheDir, "panel-uploads")
        val candidate = File(File(base, parts[0]), parts[1])
        val expected = File(File(base.canonicalFile, parts[0]), parts[1])
        if (!candidate.isFile || candidate.canonicalFile != expected ||
            candidate.length() > PanelFileContract.UPLOAD_BYTES) throw FileNotFoundException()
        return candidate
    }
    override fun getType(uri: Uri) = "application/octet-stream"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                       selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val file = file(uri)
        val columns = projection?.filter { it in listOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE) }
            ?.toTypedArray() ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(columns, 1).apply {
            addRow(columns.map { if (it == OpenableColumns.DISPLAY_NAME) file.name else file.length() })
        }
    }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException()
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
}
