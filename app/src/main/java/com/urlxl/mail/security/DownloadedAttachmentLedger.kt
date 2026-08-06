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
 * with no message metadata in it.
 *
 * Its file is **retained** by the wipe's `sharedPrefs` sweep and removed by [deleteAll] itself, and
 * only once every recorded row is actually gone. It used to be swept like any other preference file,
 * eleven steps after the deletion step — so a wipe that failed this step, promised a retry, and then
 * deleted the ledger left the resumed wipe with an empty set to iterate, which it reported as
 * success. The user was told their local data had been erased over attachment plaintext still in
 * shared Downloads. The ledger is what makes the retry meaningful, so it outlives the sweep and dies
 * with the work.
 */
object DownloadedAttachmentLedger {
    private const val TAG = "DownloadedAttachments"

    /** Referenced by [SecurityWipe]'s retained-prefs set, so the name cannot drift between the two. */
    internal const val PREFS_NAME = "com.urlxl.mail.downloaded_attachments"
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
     * Deletes every recorded row, keeps the ones it could not delete, and throws if any remain.
     *
     * Three things were wrong here, each of which let the wipe report a complete erasure over
     * attachment plaintext still sitting in shared Downloads:
     *
     * - `Result.getOrDefault(0)` mapped a **thrown** delete to `0`, which is not `< 0`, so every
     *   exception read as a successful deletion.
     * - `0` was treated as "already gone". MediaProvider also returns `0` for a row that exists and
     *   that this package may not touch — after an `_id` reassignment from an OS update or a Media
     *   Storage "Clear storage", for instance. Verified: a delete returned `0` with the file still
     *   on disk. So the count alone cannot distinguish the two; the row has to be re-queried.
     * - The ledger was cleared **before** the throw, and the `sharedPrefs` step deleted the ledger
     *   file regardless of outcome, so the `willRetry = true` the user was promised was
     *   unfulfillable: a resumed wipe found an empty ledger and reported the step as succeeded.
     *
     * Only successfully deleted URIs are removed, so a resume has exactly the remaining work — and
     * the file itself is now removed here, on success only, rather than by the sweep. Keeping the
     * *record* while dropping the *file* was the half of the fix that was missed: the two have to
     * live and die together or the retry has nothing to iterate.
     */
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
        // Keep what is still there so a resumed wipe has work to do; drop only what is really gone.
        // commit(), not apply(): a resumed wipe may start in a different process, and it also
        // flushes any record() still pending so the file delete below cannot race it.
        store.edit().putStringSet(KEY_URIS, undeleted).commit()
        if (undeleted.isNotEmpty()) {
            throw java.io.IOException("Downloads provider refused to delete: $undeleted")
        }
        // Everything recorded is gone, so the ledger has no remaining purpose. Removing it here —
        // and nowhere else — is what lets the wipe retain the file across a failed sweep without
        // leaving a stale one behind after a successful one.
        appContext.deleteSharedPreferences(PREFS_NAME)
    }

    /** True when the row is still readable, i.e. the delete did not actually remove anything. */
    private fun stillResolves(appContext: Context, uri: Uri): Boolean = runCatching {
        appContext.contentResolver.query(uri, arrayOf("_id"), null, null, null)
            ?.use { it.moveToFirst() } ?: false
    }.getOrDefault(false)
}

