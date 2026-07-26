package com.urlxl.mail.security

import android.content.Context
import android.provider.ContactsContract
import com.urlxl.mail.contacts.device.DeviceContactAccount
import com.urlxl.mail.contacts.device.DeviceContactAccountManager
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

/** Every DataStore this app owns. DataStore has no "delete everything" API, so the backing files
 *  are removed directly — safe here because a wipe is always followed by [AppRestart.relaunch],
 *  which rebuilds the graphs that own them. */
private val DATASTORE_NAMES = listOf("push_state", "contacts_state", "mail_sync_state")

/** Every SharedPreferences file this app owns except the app-lock store, which [AppLockStore.reset]
 *  handles (it also has to clear its unencrypted tripwire companion). */
private val PREFS_NAMES = listOf(
    "com.urlxl.mail.hostile_location_settings",
    "com.urlxl.mail.device_contacts",
    "com.urlxl.mail.keyword_settings",
    "com.urlxl.mail.settings",
    "push_pairing_secure",
    // A wipe runs because the device is presumed hostile, and challenge ids plus their delivery
    // timestamps are message-adjacent metadata: leaving them behind records that a sign-in
    // approval was pushed here and when.
    "com.urlxl.mail.mfa_challenges",
)

/**
 * The plaintext stores that hold mail metadata but no credentials: folder cursors keyed by
 * server-supplied folder *path*, contact cursors, the push history (sender + subject for the last
 * 30 messages), and every label the server has ever applied.
 *
 * Shared by the full wipe and by Hostile Location Protection's enable path, so the two cannot
 * drift. Enabling protection previously switched Room to in-memory and diverted only *new* push
 * payloads, leaving everything already written on disk — so "nothing from before the toggle
 * survives" was not true of the sender/subject history or the folder taxonomy.
 */
private val METADATA_PREFS_NAMES = listOf(com.urlxl.mail.KeywordSettings.PREFS_NAME)

/** Deliberately NOT in [PREFS_NAMES]: the wipe's own progress marker must outlive the wipe's own
 *  deletions, or an interruption erases the evidence that a wipe was ever started. */
private const val WIPE_STATE_PREFS = "com.urlxl.mail.wipe_state"
private const val KEY_WIPE_IN_PROGRESS = "wipe_in_progress"

/** How long the best-effort server deregistration may hold up the end of a wipe. The local data is
 *  already gone by the time this runs, so a slow or unreachable server costs nothing but a wait. */
private const val DEREGISTER_TIMEOUT_MS = 3_000L

/** Whether a wipe destroyed everything it set out to. [Incomplete] carries the step names so the
 *  caller can refuse to tell the user their data is gone when it may not be. */
sealed class WipeResult {
    object Complete : WipeResult()
    data class Incomplete(val failedSteps: List<String>) : WipeResult()
}

/**
 * Full destructive reset: runs when [LockoutPolicy.WIPE_THRESHOLD] wrong PIN attempts accumulate,
 * when the [AppLockStore] tripwire fires, and when disabling "Require Unlock to Open" needs to
 * recover a credential-gate wrapped `deviceSecret`.
 *
 * This deliberately covers far more than the Room database. The previous version deleted
 * `kypost_mail.db`, cleared the pairing prefs and reset the app lock, and left behind: the last 30
 * push payloads — **sender names and email subjects** — in the plaintext `push_state` DataStore;
 * every contact this app had synced into the OS contacts provider, which is not in this app's
 * sandbox at all; and the sync cursors, keyword filters and theme prefs. A wipe that runs
 * precisely because the device is presumed hostile cannot leave the message metadata behind.
 */
object SecurityWipe {
    private const val TAG = "SecurityWipe"

    /**
     * Performs the destructive reset described above, then drops the graph holders so nothing in
     * this process keeps serving from the closed database. Callers should still follow this with
     * [AppRestart.relaunch] to put the UI back into a coherent first-run state.
     *
     * Runs under [NonCancellable]: a wipe interrupted halfway leaves the device in a worse state
     * than either finishing or never starting, and every caller is a coroutine that may be
     * cancelled by the Activity teardown the wipe itself triggers.
     */
    suspend fun wipeAndResetApp(context: Context): WipeResult = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext
        val failed = mutableListOf<String>()

        /** Every step is individually fault-isolated — one failure must not abandon the rest — but
         *  never silently. A bare `runCatching {}` here reported a clean wipe whether or not
         *  anything was actually destroyed, on the one code path where that claim matters most. */
        fun step(name: String, body: () -> Unit) {
            runCatching(body).onFailure {
                failed += name
                android.util.Log.e(TAG, "Wipe step failed: $name", it)
            }
        }

        // A wipe interrupted halfway is worse than one that never started, and this runs while an
        // attacker is holding the device — force-stopping the app is one tap away in Settings. The
        // marker makes an interrupted wipe resumable: KyPostApp re-runs the whole thing at next
        // launch until it completes cleanly. Written with commit(), before anything is destroyed.
        markWipeInProgress(appContext, true)

        // Local plaintext FIRST, before anything that can block.
        //
        // This used to lead with tearDownPushDelivery(), whose first act is an authenticated HTTP
        // POST to deregister — up to ~20s of OkHttp connect+read timeouts before a single byte of
        // cached mail was touched. Ordering the network ahead of the destruction ranked
        // metadata-hygiene above destroying the plaintext, and handed anyone holding the device a
        // wide, reliably reproducible window in which force-stopping the app left kypost_mail.db,
        // the pairing and every cached message body fully intact.
        //
        // The database goes before the DataStores/prefs (rather than last, as it once did) because
        // nothing below it touches Room any more: clearPairing() — which does purge account-scoped
        // tables — now runs in the network phase, after this.
        step("database") { runBlocking { closeAndDeleteDatabase(appContext) } }
        step("datastores") {
            DATASTORE_NAMES.forEach { name ->
                File(appContext.filesDir, "datastore/$name.preferences_pb").delete()
            }
        }
        step("sharedPrefs") { PREFS_NAMES.forEach { appContext.deleteSharedPreferences(it) } }
        step("webViewState") { clearWebViewState(appContext) }
        step("deviceContacts") { removeSyncedDeviceContacts(appContext) }

        // Network teardown LAST, and time-boxed. The credential it authenticates with lives in
        // push_pairing_secure, which the sharedPrefs step above has already deleted — so this is
        // now a best-effort courtesy to the server rather than a precondition. Both message
        // handlers no-op without a pairing, so the "wipe re-accumulates metadata" failure the old
        // ordering guarded against cannot happen once the local state is already gone.
        step("deregister") {
            runBlocking { withTimeoutOrNull(DEREGISTER_TIMEOUT_MS) { tearDownPushDelivery(appContext) } }
        }
        // Belt and braces: clears the in-memory pairing StateFlow so anything still holding the
        // graph sees "not paired" rather than a stale pairing read before the file was deleted.
        step("clearPairingState") { runBlocking { PushRuntime.graph(appContext).repository.clearPairing() } }

        step("appLock") { AppLockStore(appContext).reset() }

        if (failed.isEmpty()) {
            markWipeInProgress(appContext, false)
            WipeResult.Complete
        } else {
            android.util.Log.e(TAG, "WIPE INCOMPLETE — failed steps: $failed")
            WipeResult.Incomplete(failed)
        }
    }

    /** Whether a previously started wipe never reached the end — see [wipeAndResetApp]. */
    fun wipeInterrupted(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_WIPE_IN_PROGRESS, false)

    private fun markWipeInProgress(appContext: Context, inProgress: Boolean) {
        val prefs = appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        if (inProgress) {
            prefs.edit().putBoolean(KEY_WIPE_IN_PROGRESS, true).commit()
        } else {
            prefs.edit().clear().commit()
        }
    }

    /**
     * Closes the current Room database instance, deletes `kypost_mail.db` (plus its `-wal`/`-shm`
     * journal files), and invalidates [DataRuntime] so the next access rebuilds it rather than
     * handing out the closed instance — which is what the old "callers MUST restart the process"
     * doc contract was standing in for.
     *
     * Shared with Hostile Location Protection's toggle handler: enabling it must delete any
     * on-disk cache written before protection was turned on, and disabling it is a harmless
     * safety net.
     */
    suspend fun closeAndDeleteDatabase(context: Context) = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext
        runCatching { DataRuntime.graph(appContext).database.close() }
            .onFailure { android.util.Log.e(TAG, "Failed to close the database before deleting it", it) }
        appContext.deleteDatabase("kypost_mail.db")
        DataRuntime.invalidate()
    }

    /**
     * Deletes the plaintext metadata stores without touching the pairing or the app lock.
     *
     * Hostile Location Protection's contract is that nothing about the user's mail is on disk. The
     * Room swap and the push-history diversion only cover data written *after* the toggle, so the
     * enable path has to remove what is already there: `push_state`'s 30-entry sender/subject
     * history, `mail_sync_state`'s cursor keys (whose *names* are server folder paths, so they leak
     * the folder taxonomy the user has opened plus per-folder read timestamps), `contacts_state`,
     * and the accumulated keyword labels.
     */
    suspend fun deletePlaintextMetadataStores(context: Context) = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext
        DATASTORE_NAMES.forEach { name ->
            runCatching { File(appContext.filesDir, "datastore/$name.preferences_pb").delete() }
                .onFailure { android.util.Log.e(TAG, "Failed to delete datastore $name", it) }
        }
        METADATA_PREFS_NAMES.forEach { name ->
            runCatching { appContext.deleteSharedPreferences(name) }
                .onFailure { android.util.Log.e(TAG, "Failed to delete prefs $name", it) }
        }
    }

    /**
     * Ends push delivery to this device before the credential that authorises the deregister is
     * destroyed, and clears the surfaces that hold already-delivered metadata.
     *
     * `clearPairing()` is purely local, so on its own it left the relay pushing to a wiped device
     * indefinitely. The UnifiedPush connector additionally keeps its own SQLite database inside this
     * app's sandbox holding the WebPush ECDH private key and auth secret, which the wipe never
     * touched — that is what let delivery keep working rather than merely being attempted.
     */
    private suspend fun tearDownPushDelivery(appContext: Context) {
        val graph = runCatching { PushRuntime.graph(appContext) }
            .onFailure { android.util.Log.e(TAG, "Push graph unavailable during teardown", it) }
            .getOrNull()
        if (graph != null) {
            runCatching { graph.repository.unpairDevice(graph.deregisterClient) }
                .onFailure { android.util.Log.w(TAG, "Server deregistration failed; local state is already gone", it) }
        }
        runCatching { com.urlxl.mail.push.UnifiedPushRegistrar.unregister(appContext) }
            .onFailure { android.util.Log.w(TAG, "UnifiedPush unregister failed", it) }
        runCatching {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken()
        }.onFailure { android.util.Log.w(TAG, "Failed to delete the FCM token", it) }
        // Already-delivered metadata: a mail notification posted while unlocked keeps sender and
        // subject in the shade after the wipe, readable with no forensics at all.
        runCatching {
            appContext.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }.onFailure { android.util.Log.e(TAG, "Failed to clear posted notifications", it) }
        runCatching { com.urlxl.mail.push.PullScheduler.cancelPeriodic(appContext) }
            .onFailure { android.util.Log.w(TAG, "Failed to cancel the pull worker", it) }
        runCatching { com.urlxl.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(appContext) }
            .onFailure { android.util.Log.w(TAG, "Failed to cancel the device-contact worker", it) }
        // The connector's own stores, which live in our sandbox but are not ours to name elsewhere.
        runCatching { appContext.deleteDatabase("unifiedpush-connector") }
            .onFailure { android.util.Log.e(TAG, "Failed to delete the UnifiedPush connector database", it) }
        runCatching { appContext.deleteSharedPreferences("unifiedpush.connector") }
            .onFailure { android.util.Log.e(TAG, "Failed to delete UnifiedPush connector prefs", it) }
    }

    /**
     * Clears Chromium's per-application profile. Tapping "Show images" on a message makes the mail
     * WebView perform real network fetches, after which cookies, `TransportSecurity` (HSTS hosts)
     * and `Network Persistent State` (alt-svc/QUIC hosts) persist under `app_webview` — a
     * host-level record of the remote-content servers contacted while reading mail. Nothing in the
     * app ever cleared any of it, and WebView's own documentation makes that the application's job.
     */
    private fun clearWebViewState(appContext: Context) {
        runCatching {
            android.webkit.WebStorage.getInstance().deleteAllData()
            android.webkit.CookieManager.getInstance().removeAllCookies(null)
            android.webkit.CookieManager.getInstance().flush()
        }
        runCatching { File(appContext.dataDir, "app_webview").deleteRecursively() }
            .onFailure { android.util.Log.e(TAG, "Failed to delete the WebView profile", it) }
        runCatching { appContext.cacheDir.deleteRecursively() }
            .onFailure { android.util.Log.e(TAG, "Failed to clear the cache dir", it) }
        runCatching { appContext.codeCacheDir.deleteRecursively() }
            .onFailure { android.util.Log.e(TAG, "Failed to clear the code cache dir", it) }
    }

    /**
     * Deletes the raw contacts this app wrote into the OS contacts provider and removes its sync
     * account. `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than a tombstone — a
     * tombstoned row still holds the contact's data until the provider next syncs, which for an
     * account we are about to remove is never.
     */
    private fun removeSyncedDeviceContacts(context: Context) {
        runCatching {
            val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
                .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
                .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
                .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
                .build()
            context.contentResolver.delete(
                uri,
                "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
                arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            )
        }.onFailure { android.util.Log.e(TAG, "Failed to delete synced device contacts", it) }

        runCatching { DeviceContactAccountManager(context).removeAccountBlocking() }
            .onFailure { android.util.Log.e(TAG, "Failed to remove contacts sync account", it) }
    }

    /**
     * Startup check for the [AppLockStore] tripwire: the encrypted app-lock file lost its contents
     * while the unencrypted marker still says a lock was configured. That means either OS-level
     * Keystore invalidation or someone deleting the keyset to disable the lock — and the old
     * behaviour of silently reporting "no lock configured" opened the inbox with every cached
     * message intact. Wipe instead, and let the user set the app up again.
     *
     * Returns true if a wipe was performed, so [com.urlxl.mail.KyPostApp] can skip the rest of its
     * startup work.
     */
    suspend fun enforceTripwire(context: Context): Boolean {
        val appContext = context.applicationContext

        // A wipe that started and never finished is resumed before anything else, including the
        // tripwire check itself — the interrupted run may have deleted the app-lock state that
        // tripwireBroken() reads, so relying on the tripwire alone would let the rest of the wipe
        // stay undone forever. Re-running is safe: every step is idempotent.
        if (wipeInterrupted(appContext)) {
            android.util.Log.e(TAG, "Previous wipe did not complete; resuming")
            wipeAndResetApp(appContext)
            return true
        }

        if (!AppLockStore(appContext).tripwireBroken()) return false
        android.util.Log.e(TAG, "App-lock state vanished while a lock was configured; wiping")
        wipeAndResetApp(appContext)
        return true
    }
}
