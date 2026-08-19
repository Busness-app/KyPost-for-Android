package org.kysecurity.mail.security

import android.content.Context
import android.net.Uri

/** Downloads rows outlive the sandbox wipe; plain prefs so it survives the database delete. */
object DownloadedAttachmentLedger {
    private const val TAG = "DownloadedAttachments"

    /** Referenced by [SecurityWipe]'s retained-prefs set, so the name cannot drift between the two. */
    internal const val PREFS_NAME = "org.kysecurity.mail.downloaded_attachments"
    private const val KEY_URIS = "uris"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun record(context: Context, uri: Uri) {
        val store = prefs(context)
        // A fresh set: SharedPreferences returns the *live* set instance from its cache, and
        // mutating that in place is documented as unsupported and does not persist reliably.
        val updated = LinkedHashSet(store.getStringSet(KEY_URIS, emptySet()).orEmpty())
        updated += uri.toString()
        store.edit().putStringSet(KEY_URIS, updated).apply()
    }

    /** Keeps only the URIs it could not delete, then throws, so a resume has the rest. */
    fun deleteAll(context: Context) {
        val appContext = context.applicationContext
        val store = prefs(appContext)
        val recorded = store.getStringSet(KEY_URIS, emptySet()).orEmpty()
        val undeleted = LinkedHashSet<String>()
        recorded.forEach { raw ->
            val uri = Uri.parse(raw)
            val deleted = runCatching { appContext.contentResolver.delete(uri, null, null) }
                .onFailure { android.util.Log.w(TAG, "Could not delete $raw", it) }
                .getOrNull()
            when {
                // A thrown delete is a failure, never a success.
                deleted == null -> undeleted += raw
                deleted > 0 -> Unit
                // Zero rows affected is ambiguous. It is only "already gone" if the row really is
                // gone, so ask the provider rather than assuming the outcome we wanted.
                stillResolves(appContext, uri) -> undeleted += raw
            }
        }
        // commit(), not apply(): a resumed wipe may start in a different process.
        store.edit().putStringSet(KEY_URIS, undeleted).commit()
        if (undeleted.isNotEmpty()) {
            throw java.io.IOException("Downloads provider refused to delete: $undeleted")
        }
        // Delete the ledger only on full success, so a failed sweep keeps the file to retry from.
        appContext.deleteSharedPreferences(PREFS_NAME)
    }

    /** True when the row is still readable, i.e. the delete did not actually remove anything. */
    private fun stillResolves(appContext: Context, uri: Uri): Boolean = runCatching {
        appContext.contentResolver.query(uri, arrayOf("_id"), null, null, null)
            ?.use { it.moveToFirst() } ?: false
    }.getOrDefault(false)
}

