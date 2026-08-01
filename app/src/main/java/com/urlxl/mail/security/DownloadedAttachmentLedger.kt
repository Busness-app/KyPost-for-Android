package com.urlxl.mail.security

import android.content.Context
import android.net.Uri

/**
 * Remembers the MediaStore rows this app wrote into shared Downloads, so [SecurityWipe] can delete
 * them.
 *
 * Attachments saved with Hostile Location Protection *off* — the default — go to shared storage on a
 * single unprompted tap ([com.urlxl.mail.EmailDetailActivity.downloadAttachment]). Those files live
 * outside the app sandbox, so nothing the wipe deletes reaches them: they survived the wipe, the
 * app-lock reset and the re-pair, while the first screen afterwards told the user "Local data on
 * this device has been erased". Message attachments are frequently the most sensitive thing the app
 * handles, so that claim has to cover them.
 *
 * Deliberately a plain preference file rather than a Room table: it has to be readable and writable
 * *after* [SecurityWipe] has closed and deleted the database, and it is a set of opaque URI strings
 * with no message metadata in it. Its own file is enumerated and deleted by the wipe's `sharedPrefs`
 * step, which runs after the deletion step below — so the ledger does not outlive the files it
 * tracks.
 */
object DownloadedAttachmentLedger {
    private const val TAG = "DownloadedAttachments"
    private const val PREFS_NAME = "com.urlxl.mail.downloaded_attachments"
    private const val KEY_URIS = "uris"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Records a row this app inserted into MediaStore Downloads. */
    fun record(context: Context, uri: Uri) {
        val store = prefs(context)
        // A fresh set: SharedPreferences returns the *live* set instance from its cache, and
        // mutating that in place is documented as unsupported and does not persist reliably.
        val updated = LinkedHashSet(store.getStringSet(KEY_URIS, emptySet()).orEmpty())
        updated += uri.toString()
        store.edit().putStringSet(KEY_URIS, updated).apply()
    }

    /**
     * Deletes every recorded row and clears the ledger.
     *
     * Throws if any row is still resolvable and refused deletion, so the wipe records the step as
     * failed rather than reporting a complete erasure over files that are still there. A row the
     * user has already deleted themselves resolves to zero rows affected and is not an error.
     */
    fun deleteAll(context: Context) {
        val appContext = context.applicationContext
        val store = prefs(appContext)
        val recorded = store.getStringSet(KEY_URIS, emptySet()).orEmpty()
        val undeleted = mutableListOf<String>()
        recorded.forEach { raw ->
            val result = runCatching { appContext.contentResolver.delete(Uri.parse(raw), null, null) }
            result.onFailure { android.util.Log.w(TAG, "Could not delete $raw", it) }
            // A negative count is the provider reporting it did not act; zero means the row is
            // already gone, which is the outcome we wanted.
            if (result.getOrDefault(0) < 0) undeleted += raw
        }
        store.edit().remove(KEY_URIS).commit()
        if (undeleted.isNotEmpty()) {
            throw java.io.IOException("Downloads provider refused to delete: $undeleted")
        }
    }
}
