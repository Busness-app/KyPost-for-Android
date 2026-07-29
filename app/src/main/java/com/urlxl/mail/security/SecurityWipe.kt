package com.urlxl.mail.security

import android.content.Context
import android.provider.ContactsContract
import com.urlxl.mail.InMemoryPlaintext
import com.urlxl.mail.contacts.device.DeviceContactAccount
import com.urlxl.mail.contacts.device.DeviceContactAccountManager
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

/** Every DataStore this app owns. DataStore has no "delete everything" API, so the backing files
 *  are removed directly — safe here because a wipe is always followed by [AppRestart.relaunch],
 *  which rebuilds the graphs that own them. */
private val DATASTORE_NAMES = listOf("push_state", "contacts_state", "mail_sync_state")

/**
 * SharedPreferences files the enumeration in [deleteAllSharedPrefs] must NOT touch.
 *
 * The two app-lock files belong to [AppLockStore.reset], which deletes the unencrypted tripwire
 * *before* the encrypted store — an order this enumeration cannot promise. The wipe marker has to
 * outlive the wipe's own deletions, or an interruption erases the evidence that a wipe was started.
 * The UnifiedPush connector's file is deleted by the dedicated `unifiedPushPrefs` step, which runs
 * after `unifiedPushUnregister` because it holds the distributor selection that
 * `UnifiedPush.unregister` needs to actually unsubscribe. That step is what makes excluding it here
 * safe; the exclusion previously rested on the unregister step deleting it, which it never did.
 */
private val PREFS_NAMES_RETAINED = setOf(
    "app_lock_secure",
    "app_lock_tripwire",
    "com.urlxl.mail.wipe_state",
    "unifiedpush.connector",
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

/** Listed in [PREFS_NAMES_RETAINED]: the wipe's own progress marker must outlive the wipe's own
 *  deletions, or an interruption erases the evidence that a wipe was ever started. */
private const val WIPE_STATE_PREFS = "com.urlxl.mail.wipe_state"
private const val KEY_WIPE_IN_PROGRESS = "wipe_in_progress"
private const val KEY_WIPE_ATTEMPTS = "wipe_attempts"

/**
 * How many times an incomplete wipe may be resumed at startup before the app stops retrying.
 *
 * The marker used to be cleared only on a fully clean run, with no ceiling — so a step that fails
 * *permanently* meant the app wiped itself on every launch, forever, with no way for the user to
 * get past it. That was not hypothetical: [clearWebViewState] recursively deleted `cacheDir` while
 * the process was live and OkHttp, WebView and the code cache were recreating files inside it, and
 * `deleteRecursively()` reports false for any partial delete. Losing that race is routine.
 *
 * Three attempts is enough to ride out a transient failure (a file held open, a provider that was
 * briefly unavailable) and few enough that a permanent one surfaces as a reported problem rather
 * than a brick.
 */
private const val MAX_WIPE_RESUMES = 3

/**
 * Whether a wipe destroyed everything it set out to. [Incomplete] carries the step names so the
 * caller can refuse to tell the user their data is gone when it may not be.
 *
 * Scoped to **local destruction**. The best-effort server deregistration is reported in the log,
 * not here: an unreachable relay says nothing about whether the data on this device is gone, and
 * folding it in would both lie to an offline user and keep the resume marker set forever.
 */
sealed class WipeResult {
    object Complete : WipeResult()
    data class Incomplete(val failedSteps: List<String>) : WipeResult()
}

/**
 * Full destructive reset: runs when [LockoutPolicy.WIPE_THRESHOLD] wrong PIN attempts accumulate,
 * when the [AppLockStore] tripwire fires, and when disabling "Require Unlock to Open" needs to
 * recover a credential-gate wrapped `deviceSecret`.
 *
 * Its scope is deliberately wider than the Room database: the push history holds sender names and
 * subjects, and the contacts this app synced live in the OS provider, outside its sandbox
 * entirely. A wipe that runs precisely because the device is presumed hostile cannot leave message
 * metadata behind — and must never report [WipeResult.Complete] unless every step really ran.
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

        /**
         * Every step is individually fault-isolated — one failure must not abandon the rest — but
         * never silently. A bare `runCatching {}` here reported a clean wipe whether or not
         * anything was actually destroyed, on the one code path where that claim matters most.
         *
         * **Nothing below may catch its own exceptions.** Three steps used to delegate to helpers
         * whose every statement sat in its own `runCatching { }.onFailure { Log }`, so the step
         * could not fail however badly it went — including `deviceContacts`, which deletes the
         * user's contacts out of the OS provider, outside this app's sandbox. `Complete` was
         * therefore a claim the code structurally could not support. Let it throw; that is what
         * this function is for.
         *
         * Swallowing [kotlinx.coroutines.CancellationException] here is deliberate and is the one
         * place it is right: this whole block runs under [NonCancellable], so it cannot be *our*
         * job being cancelled, and abandoning the remaining destruction because one step was
         * interrupted leaves the device in the half-wiped state the marker exists to prevent.
         */
        suspend fun step(name: String, body: suspend () -> Unit) {
            runCatching { body() }.onFailure {
                failed += name
                android.util.Log.e(TAG, "Wipe step failed: $name", it)
            }
        }

        // A wipe interrupted halfway is worse than one that never started, and this runs while an
        // attacker is holding the device — force-stopping the app is one tap away in Settings. The
        // marker makes an interrupted wipe resumable: KyPostApp re-runs the whole thing at next
        // launch until it completes cleanly. Written with commit(), before anything is destroyed.
        markWipeInProgress(appContext)

        // Captured BEFORE the destruction below, and restored after it.
        //
        // `com.urlxl.mail.hostile_location_settings` is not in PREFS_NAMES_RETAINED, so the
        // enumeration in deleteAllSharedPrefs removes it and the flag reverts to its `false`
        // default. This wipe runs *precisely* when the device is presumed hostile — ten wrong PINs,
        // or the tripwire firing — and its side effect was therefore to silently switch off the one
        // feature that exists for that exact situation. The user re-paired on a device the app had
        // just decided was compromised, and every message body went straight back to
        // `kypost_mail.db` in plaintext. A wipe may destroy data; it must not downgrade posture.
        val hostileLocationWasEnabled = runCatching { HostileLocationSettings(appContext).isEnabled() }
            .onFailure { android.util.Log.e(TAG, "Could not read the protection flag before wiping", it) }
            .getOrDefault(false)

        // Captured BEFORE the destruction below, which deletes `push_pairing_secure` in the
        // sharedPrefs step. The deregister runs last on purpose — destroying the plaintext must not
        // wait on a network round trip — but it authenticates with a credential that lives in the
        // file that step removes, so reading it at call time meant the deregister could only ever
        // report "Device is not paired" and the server kept pushing to a wiped device forever.
        // Holding the secret in memory for the duration of the wipe costs nothing: this process is
        // about to be relaunched, and the same secret was already in memory to get here.
        val pairingForDeregister = runCatching { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }
            .onFailure { android.util.Log.w(TAG, "Could not read the pairing before wiping; deregister will be skipped", it) }
            .getOrNull()

        // ORDER IS THE POINT: local plaintext first, network last. An attacker holding the device
        // can force-stop the app at any moment, so every step that blocks — above all the ~20s of
        // OkHttp timeouts in the deregister — has to come after the destruction, not before it.
        //
        // The in-memory draft leads because it needs no I/O and is the most sensitive thing here:
        // AppRestart relaunches into the same JVM rather than killing the process, so an uncleared
        // draft is restorable from the compose screen in the attacker's session.
        step("inMemoryPlaintext") {
            val unclearedHolders = InMemoryPlaintext.clearAll()
            if (unclearedHolders.isNotEmpty()) {
                throw IOException("Process-scoped plaintext holders failed to clear: $unclearedHolders")
            }
        }
        step("database") { closeAndDeleteDatabase(appContext) }
        step("datastores") {
            DATASTORE_NAMES.forEach { name ->
                File(appContext.filesDir, "datastore/$name.preferences_pb").delete()
            }
        }

        // Local push teardown BEFORE the network call, not after it. These are the pieces that
        // keep delivery working — the connector's own SQLite database holds the WebPush ECDH
        // private key and auth secret — plus the already-delivered metadata sitting in the shade.
        // They used to sit *after* the deregister inside a `withTimeoutOrNull(3s)` whose bound was
        // set to exactly the deregister client's own 3s `callTimeout`, so the two raced and an
        // unreachable server (airplane mode: one swipe, before burning ten PINs) reliably cancelled
        // the coroutine before any of this ran. None of it needs the network; none of it belongs
        // behind something that does.
        step("cancelNotifications") {
            // A mail notification posted while unlocked keeps sender and subject in the shade after
            // the wipe, readable with no forensics at all.
            appContext.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }
        // UNREGISTER FIRST, THEN DELETE THE CONNECTOR'S STATE. Reversed, the unregister ran against
        // a connector whose own registration records had just been deleted, so it had nothing left
        // to tell the distributor to unsubscribe — the device stayed subscribed at the distributor
        // and its push server. The `PREFS_NAMES_RETAINED` note already applied this reasoning to
        // the connector's preferences file and stopped short of its database.
        step("unifiedPushUnregister") { com.urlxl.mail.push.UnifiedPushRegistrar.unregister(appContext) }
        step("unifiedPushDatabase") {
            // Lives in our sandbox but is not ours to name elsewhere. Holds the WebPush ECDH
            // private key and auth secret.
            appContext.deleteDatabase("unifiedpush-connector")
        }
        step("unifiedPushPrefs") {
            // Explicit, because `PREFS_NAMES_RETAINED` excludes this file from the enumeration and
            // claimed the unregister step removed it. It does not: `UnifiedPushRegistrar.unregister`
            // delegates to `UnifiedPush.unregister`, which unsubscribes the instance and
            // deliberately keeps the distributor selection so a later re-register reuses it. So the
            // record of which push distributor this user runs survived a wipe performed precisely
            // because the device is presumed hostile.
            if (!appContext.deleteSharedPreferences("unifiedpush.connector")) {
                // Absent is the normal case (UnifiedPush was never selected); only a file that is
                // there and will not go is a failure.
                val file = File(File(appContext.dataDir, "shared_prefs"), "unifiedpush.connector.xml")
                if (file.exists()) throw IOException("Failed to delete unifiedpush.connector preferences")
            }
        }
        step("fcmToken") { com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken() }
        step("pullWorker") { com.urlxl.mail.push.PullScheduler.cancelPeriodic(appContext) }
        step("deviceContactWorker") { com.urlxl.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(appContext) }

        // After the connector teardown above, which needs `unifiedpush.connector` to still hold the
        // distributor selection that `UnifiedPush.unregister` reads.
        step("sharedPrefs") { deleteAllSharedPrefs(appContext) }
        step("webViewState") { clearWebViewState(appContext) }
        step("deviceContactRows") { deleteSyncedDeviceContactRows(appContext) }
        step("deviceContactAccount") { DeviceContactAccountManager(appContext).removeAccountBlocking() }

        // Network LAST, and bounded only by the deregister client's own `callTimeout` (see
        // PushGraph.deregisterClient). No `withTimeoutOrNull`: coroutine cancellation cannot
        // interrupt a thread blocked in a socket read, so it never delivered the bound it claimed —
        // all it did was skip whatever came after it, which is why every local teardown above was
        // moved in front of this call.
        //
        // Deliberately NOT folded into `failed`. [WipeResult.Incomplete] means "local data may
        // still be on disk" — that is what the UI says on the back of it — and an unreachable relay
        // says nothing about local data, every byte of which is already gone by this line. Counting
        // it would tell an offline user their mail might still be here when it is not, and would
        // keep the resume marker set so the app re-ran the whole destructive wipe at every launch
        // until the server came back. Logged loudly instead: the consequence is server-side (the
        // relay keeps pushing to a device that will never answer), and the remedy is server-side
        // too.
        val deregistered = runCatching {
            PushRuntime.graph(appContext).repository
                .unpairDevice(PushRuntime.graph(appContext).deregisterClient, pairingForDeregister)
        }.getOrElse { com.urlxl.mail.push.DeregisterResult.Error(it.message ?: "deregister threw") }
        if (deregistered is com.urlxl.mail.push.DeregisterResult.Error) {
            android.util.Log.e(
                TAG,
                "Local wipe finished but server deregistration failed (${deregistered.message}); " +
                    "the relay may keep pushing to this device until it is removed server-side",
            )
        }

        // Belt and braces: clears the in-memory pairing StateFlow so anything still holding the
        // graph sees "not paired" rather than a stale pairing read before the file was deleted.
        // unpairDevice above already does this, but not if it threw. This one IS a local step.
        step("clearPairingState") { PushRuntime.graph(appContext).repository.clearPairing() }

        step("appLock") { AppLockStore(appContext).reset() }

        // Re-assert the protection posture the deletions above erased. Runs after the sharedPrefs
        // step on purpose — writing it earlier would just be deleted again. A step, not a bare
        // call, so a failure to restore it is reported rather than leaving the user believing
        // protection survived. Nothing is re-enabled that was not already on.
        if (hostileLocationWasEnabled) {
            step("restoreHostileLocationProtection") { HostileLocationSettings(appContext).setEnabled(true) }
        }

        if (failed.isEmpty()) {
            clearWipeMarker(appContext)
            WipeResult.Complete
        } else {
            android.util.Log.e(TAG, "WIPE INCOMPLETE — failed steps: $failed")
            // Past the ceiling, stop asking the app to re-wipe itself at every launch. The steps
            // that did succeed are still done; what remains is reported, not retried forever.
            if (wipeAttempts(appContext) >= MAX_WIPE_RESUMES) {
                android.util.Log.e(TAG, "Wipe failed $MAX_WIPE_RESUMES times; giving up on resuming it")
                clearWipeMarker(appContext)
            }
            WipeResult.Incomplete(failed)
        }
    }

    /** Whether a previously started wipe never reached the end — see [wipeAndResetApp]. */
    fun wipeInterrupted(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_WIPE_IN_PROGRESS, false)

    private fun wipeAttempts(appContext: Context): Int =
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).getInt(KEY_WIPE_ATTEMPTS, 0)

    /** Sets the marker and counts this attempt, in one `commit()`, before anything is destroyed. */
    private fun markWipeInProgress(appContext: Context) {
        val prefs = appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putBoolean(KEY_WIPE_IN_PROGRESS, true)
            .putInt(KEY_WIPE_ATTEMPTS, prefs.getInt(KEY_WIPE_ATTEMPTS, 0) + 1)
            .commit()
    }

    private fun clearWipeMarker(appContext: Context) {
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).edit().clear().commit()
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

        // ORDER MATTERS, and it used to be wrong in both directions.
        //
        // Quiesce first: `invalidate()` only makes the *next* `get()` rebuild, so work already in
        // flight keeps its own reference to the instance about to be closed, and closing it out
        // from under a pool thread is an uncaught exception on a non-UI thread — a process kill.
        //
        // Then `take()`, not `invalidate()` + `graph()`: the latter would build a brand-new database
        // and close *that*, leaving the live one open. Taking removes it from the holder and hands
        // back the instance actually in use, in one step, so no later caller can be given it either.
        val settled = com.urlxl.mail.MailBackgroundExecutor.quiesce()
        val doomed = DataRuntime.takeGraph()
        runCatching { doomed?.database?.close() }
            .onFailure { android.util.Log.e(TAG, "Failed to close the database before deleting it", it) }
        val deleted = appContext.deleteDatabase("kypost_mail.db")
        // Reported, not merely logged. `deleteDatabase` returns false when the file is still there,
        // which after an unquiesced teardown is exactly what "mail work is still holding it open"
        // looks like — and the cached message bodies are the single most sensitive thing a wipe is
        // supposed to destroy. The quiesce result is folded in so the cause is named rather than
        // guessed at from a bare "false".
        if (!deleted && appContext.getDatabasePath("kypost_mail.db").exists()) {
            throw IOException(
                "kypost_mail.db still exists after deletion" +
                    if (!settled) " (mail work did not quiesce first)" else "",
            )
        }
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
     * Every SharedPreferences file this app owns, minus [PREFS_NAMES_RETAINED].
     *
     * Enumerated rather than listed by name. The list this replaced claimed to be complete and was
     * not — `com.urlxl.mail.app_lock_settings` had never been added to it — and a hardcoded list
     * silently goes stale every time a preference file is introduced.
     *
     * Throws on the first failure so [wipeAndResetApp] records the step as failed.
     */
    private fun deleteAllSharedPrefs(appContext: Context) {
        val dir = File(appContext.dataDir, "shared_prefs")
        // Null means the directory could not be enumerated, which is not the same as "there is
        // nothing here" — `.orEmpty()` alone turned "I cannot see what needs deleting" into a
        // clean pass.
        val files = dir.listFiles { file -> file.name.endsWith(".xml") }
            ?: if (dir.exists()) throw IOException("Could not enumerate $dir") else emptyArray()
        val names = files
            .map { it.name.removeSuffix(".xml") }
            .filterNot { it in PREFS_NAMES_RETAINED }
        val undeleted = names.filterNot { appContext.deleteSharedPreferences(it) }
        if (undeleted.isNotEmpty()) {
            throw IOException("Failed to delete shared preferences: $undeleted")
        }
    }

    /**
     * Clears Chromium's per-application profile: tapping "Show images" makes the mail WebView
     * perform real network fetches, after which cookies, `TransportSecurity` (HSTS hosts) and
     * `Network Persistent State` (alt-svc/QUIC hosts) persist under `app_webview` as a host-level
     * record of the remote-content servers contacted while reading mail.
     *
     * Nothing here is caught. Every statement used to sit inside a bare `runCatching {}`, so a
     * failure could not reach [wipeAndResetApp]'s `failed` list and the wipe reported
     * [WipeResult.Complete] with the browsing state still on disk — the one claim that must never
     * be made falsely. The WebView statics additionally run on the main thread: this function is
     * called from `Dispatchers.IO`, and initialising the WebView provider off the UI thread throws.
     */
    private suspend fun clearWebViewState(appContext: Context) {
        withContext(Dispatchers.Main) {
            android.webkit.WebStorage.getInstance().deleteAllData()
            android.webkit.CookieManager.getInstance().removeAllCookies(null)
            android.webkit.CookieManager.getInstance().flush()
        }
        // `app_webview` is the directory that actually holds the host-level record — cookies,
        // TransportSecurity, Network Persistent State — so a partial delete here is exactly the
        // state this must not call Complete. deleteRecursively() reports false rather than
        // throwing, hence the explicit check.
        val profile = File(appContext.dataDir, "app_webview")
        if (profile.exists() && !profile.deleteRecursively()) {
            throw IOException("Failed to delete the WebView profile directory")
        }

        // The caches are emptied child by child, and their failures are logged rather than thrown.
        //
        // `deleteRecursively()` on `cacheDir` itself was the single most likely cause of a
        // permanently incomplete wipe: this runs in a live process where OkHttp, WebView and ART
        // are still creating files underneath it, so losing that race is routine — and an
        // Incomplete wipe used to re-run at every launch forever (see MAX_WIPE_RESUMES). Deleting
        // the directory itself is also wrong: code that writes to `cacheDir` afterwards expects it
        // to exist. Nothing security-relevant is unique to these two directories anyway; the mail
        // bodies are in the database and the browsing state is in `app_webview`, both handled
        // above and both fatal on failure.
        listOf(appContext.cacheDir, appContext.codeCacheDir).forEach { dir ->
            dir.listFiles().orEmpty().forEach { child ->
                if (!child.deleteRecursively()) {
                    android.util.Log.w(TAG, "Could not fully delete cache entry ${child.name}")
                }
            }
        }
    }

    /**
     * Deletes the raw contacts this app wrote into the OS contacts provider.
     * `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than a tombstone — a tombstoned row
     * still holds the contact's data until the provider next syncs, which for an account we are
     * about to remove is never.
     *
     * Throws on failure, and is a separate step from removing the account, because this is the one
     * thing a wipe destroys that lives **outside this app's sandbox**: real names, phone numbers
     * and email addresses in the OS provider. It used to wrap both operations in their own
     * `runCatching { }.onFailure { Log }`, so `step("deviceContacts")` could not fail and the wipe
     * reported `Complete` with the user's contacts still on the device.
     */
    private fun deleteSyncedDeviceContactRows(context: Context) {
        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
            .build()
        val deleted = context.contentResolver.delete(
            uri,
            "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
            arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
        )
        // A negative count is the provider reporting it did not act. Zero is legitimate (sync was
        // never enabled), so it is not an error — but it must not be *assumed*, which is what
        // discarding the return value did.
        if (deleted < 0) {
            throw IOException("Contacts provider refused to delete this app's raw contacts")
        }
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

    /**
     * Completes once the startup tripwire check has finished, carrying whether it wiped.
     *
     * This exists because the check is a **gate**, and it was not being used as one.
     * [com.urlxl.mail.KyPostApp] ran [enforceTripwire] inside an `appScope.launch` on
     * `Dispatchers.IO` under a comment reading *"Runs before anything reads cached data"* —
     * a guarantee `Application.onCreate` cannot make, since it returns immediately and the launcher
     * Activity starts while that coroutine is still doing a MasterKey round trip and a Tink keyset
     * load. An attacker who deletes the app-lock keyset to disable the lock therefore got the
     * inbox rendered with every cached message intact, and the wipe landed a few hundred
     * milliseconds later, tearing the database out from under a live screen.
     *
     * [com.urlxl.mail.security.LockedActivity] awaits this before doing anything, so the verdict is
     * in before any screen can read data. Kept here rather than in `KyPostApp` so a test — and any
     * future entry point — can await the same signal without reaching into the Application object.
     */
    val startupVerdict: kotlinx.coroutines.CompletableDeferred<Boolean> =
        kotlinx.coroutines.CompletableDeferred()
}
