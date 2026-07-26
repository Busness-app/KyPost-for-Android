package com.urlxl.mail.security

import android.content.Context
import android.provider.ContactsContract
import com.urlxl.mail.contacts.device.DeviceContactAccount
import com.urlxl.mail.contacts.device.DeviceContactAccountManager
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
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
    /**
     * Performs the destructive reset described above, then drops the graph holders so nothing in
     * this process keeps serving from the closed database. Callers should still follow this with
     * [AppRestart.relaunch] to put the UI back into a coherent first-run state.
     *
     * Runs under [NonCancellable]: a wipe interrupted halfway leaves the device in a worse state
     * than either finishing or never starting, and every caller is a coroutine that may be
     * cancelled by the Activity teardown the wipe itself triggers.
     */
    suspend fun wipeAndResetApp(context: Context) = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext

        // Stop delivery FIRST, while the credential still exists to authenticate the deregister.
        // Without this the relay kept pushing to a wiped device, and both message handlers act with
        // no pairing state at all — so the next inbound mail posted full sender and subject (the
        // lock flag had just been cleared, so isLocked() read false) and wrote them straight back
        // to a rebuilt push_state DataStore. A wipe that re-accumulates the metadata it exists to
        // destroy is worse than no wipe, because the user believes it worked.
        tearDownPushDelivery(appContext)

        removeSyncedDeviceContacts(appContext)

        // Clears the in-memory pairing StateFlow as well as the encrypted file, so anything still
        // holding the graph sees "not paired" rather than a stale pairing.
        runCatching { PushRuntime.graph(appContext).repository.clearPairing() }

        clearWebViewState(appContext)

        DATASTORE_NAMES.forEach { name ->
            runCatching { File(appContext.filesDir, "datastore/$name.preferences_pb").delete() }
        }
        PREFS_NAMES.forEach { name -> runCatching { appContext.deleteSharedPreferences(name) } }

        // Deliberately LAST. Every step above may touch Room — `clearPairing` now purges the
        // account-scoped tables for the unpair path, and `DataRuntime.graph()` rebuilds a
        // disk-backed database on demand. Deleting the file first therefore recreated it moments
        // later, leaving `kypost_mail.db` on disk after a "successful" wipe.
        closeAndDeleteDatabase(appContext)

        AppLockStore(appContext).reset()
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
        }
        METADATA_PREFS_NAMES.forEach { name -> runCatching { appContext.deleteSharedPreferences(name) } }
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
        val graph = runCatching { PushRuntime.graph(appContext) }.getOrNull()
        if (graph != null) {
            runCatching { graph.repository.unpairDevice(graph.deregisterClient) }
        }
        runCatching { com.urlxl.mail.push.UnifiedPushRegistrar.unregister(appContext) }
        runCatching {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken()
        }
        // Already-delivered metadata: a mail notification posted while unlocked keeps sender and
        // subject in the shade after the wipe, readable with no forensics at all.
        runCatching {
            appContext.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }
        runCatching { com.urlxl.mail.push.PullScheduler.cancelPeriodic(appContext) }
        runCatching { com.urlxl.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(appContext) }
        // The connector's own stores, which live in our sandbox but are not ours to name elsewhere.
        runCatching { appContext.deleteDatabase("unifiedpush-connector") }
        runCatching { appContext.deleteSharedPreferences("unifiedpush.connector") }
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
        runCatching { appContext.cacheDir.deleteRecursively() }
        runCatching { appContext.codeCacheDir.deleteRecursively() }
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
        }.onFailure { android.util.Log.e("SecurityWipe", "Failed to delete synced device contacts", it) }

        runCatching { DeviceContactAccountManager(context).removeAccountBlocking() }
            .onFailure { android.util.Log.e("SecurityWipe", "Failed to remove contacts sync account", it) }
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
        if (!AppLockStore(appContext).tripwireBroken()) return false
        android.util.Log.e("SecurityWipe", "App-lock state vanished while a lock was configured; wiping")
        wipeAndResetApp(appContext)
        return true
    }
}
