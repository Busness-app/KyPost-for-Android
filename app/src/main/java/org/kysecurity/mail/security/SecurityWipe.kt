package org.kysecurity.mail.security

import android.content.Context
import android.provider.ContactsContract
import org.kysecurity.mail.InMemoryPlaintext
import org.kysecurity.mail.contacts.device.DeviceContactAccount
import org.kysecurity.mail.contacts.device.DeviceContactAccountManager
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException

/** Every DataStore this app owns. DataStore has no "delete everything" API, so the backing files
 *  are removed directly — safe here because a wipe is always followed by [AppRestart.relaunch],
 *  which rebuilds the graphs that own them. */
private val DATASTORE_NAMES = listOf("push_state", "contacts_state", "mail_sync_state")

/**
 * Files [deleteAllSharedPrefs] must NOT sweep, each because a named step owns it and needs it
 * *later* in the run: [AppLockStore.reset] (ordering), the wipe marker and the attachment ledger
 * (records of work still owed, so a resumed wipe has something to iterate), and the UnifiedPush
 * connector's file (holds the distributor selection `unifiedPushUnregister` reads).
 */
private val PREFS_NAMES_RETAINED = setOf(
    "app_lock_secure",
    "app_lock_tripwire",
    "org.kysecurity.mail.wipe_state",
    "unifiedpush.connector",
    DownloadedAttachmentLedger.PREFS_NAME,
)

/**
 * Plaintext mail metadata, no credentials: folder cursors (whose *keys* are server folder paths),
 * contact cursors, the 30-entry sender/subject push history, and accumulated labels.
 *
 * Shared by the full wipe and Hostile Location Protection's enable path so the two cannot drift.
 */
private val METADATA_PREFS_NAMES = listOf(org.kysecurity.mail.KeywordSettings.PREFS_NAME)

/** Listed in [PREFS_NAMES_RETAINED]: the wipe's own progress marker must outlive the wipe's own
 *  deletions, or an interruption erases the evidence that a wipe was ever started. */
private const val WIPE_STATE_PREFS = "org.kysecurity.mail.wipe_state"
private const val KEY_WIPE_IN_PROGRESS = "wipe_in_progress"
private const val KEY_WIPE_ATTEMPTS = "wipe_attempts"

/**
 * "Stop retrying by itself" — set once a wipe has exhausted [MAX_WIPE_RESUMES] with steps still
 * failing. Deliberately does **not** clear [KEY_WIPE_IN_PROGRESS]: that marker is the only durable
 * record that data may still be on disk, and it must survive until a run completes cleanly.
 */
private const val KEY_WIPE_ABANDONED = "wipe_abandoned"

/** The step names of the abandoned wipe, so the permanent state can name what was left behind on
 *  every later launch rather than only on the run that gave up. */
private const val KEY_WIPE_FAILED_STEPS = "wipe_failed_steps"

/**
 * The Hostile Location Protection posture as it was at the *start* of the wipe, stored in the one
 * preferences file the wipe retains — the `sharedPrefs` step deletes the flag's own file, so a
 * resumed run has to read it from here or it silently reverts the setting to `false`.
 */
private const val KEY_HOSTILE_LOCATION_WAS_ENABLED = "hostile_location_was_enabled"

/**
 * How many times an incomplete wipe may be resumed at startup before the app stops retrying.
 *
 * Enough to ride out a transient failure (a file held open, a provider briefly unavailable), few
 * enough that a permanent one surfaces as a reported problem rather than an app that wipes itself
 * on every launch forever.
 */
private const val MAX_WIPE_RESUMES = 3

/**
 * Ceiling on the Play Services token/installation teardown.
 *
 * Short for the same reason the deregister's is: this runs while an attacker may be holding the
 * device, and a hostile network must not be able to hold the wipe open.
 */
private const val FCM_TEARDOWN_TIMEOUT_MS = 3_000L

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

    /**
     * `willRetry = false` is **terminal**, not informational: the app has stopped resuming the wipe
     * by itself, [LockedActivity] blocks every gated screen on it, and the state survives launches
     * (see [KEY_WIPE_ABANDONED]) until a reinstall.
     */
    data class Incomplete(
        val failedSteps: List<String>,
        val willRetry: Boolean = true,
    ) : WipeResult()
}

/**
 * Full destructive reset: runs on the user's configured run of wrong PIN attempts, and when the
 * [AppLockStore] tripwire fires.
 *
 * Wider than the Room database on purpose — the push history holds senders and subjects, and the
 * synced contacts live in the OS provider, outside this sandbox. It must never report
 * [WipeResult.Complete] unless every step really ran.
 */
object SecurityWipe {
    private const val TAG = "SecurityWipe"

    /**
     * Performs the reset, then drops the graph holders. Follow with [AppRestart.relaunch].
     *
     * [NonCancellable]: every caller is a coroutine the wipe's own teardown may cancel, and a
     * half-finished wipe is worse than either outcome.
     */
    suspend fun wipeAndResetApp(context: Context): WipeResult = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext
        val failed = mutableListOf<String>()

        /**
         * Fault-isolates one step without silencing it: a failure is recorded in [failed], which is
         * what stops [WipeResult.Complete] being claimed over data that is still here.
         *
         * **Nothing below may catch its own exceptions** — a step that cannot fail cannot be
         * reported. Swallowing `CancellationException` is right here and nowhere else: this runs
         * under [NonCancellable], so it is never *our* job being cancelled.
         */
        suspend fun step(name: String, body: suspend () -> Unit) {
            runCatching { body() }.onFailure {
                failed += name
                android.util.Log.e(TAG, "Wipe step failed: $name", it)
            }
        }

        // Captured BEFORE the destruction and restored after: the sweep deletes this flag's file,
        // and a wipe that runs *because* the device is presumed hostile must not switch off the
        // feature for that exact situation. A wipe may destroy data; it must not downgrade posture.
        // Persisted by markWipeInProgress so a resumed run reads it from the retained file.
        val currentlyEnabled = runCatching { HostileLocationSettings(appContext).isEnabled() }
            .onFailure { android.util.Log.e(TAG, "Could not read the protection flag before wiping", it) }
            .getOrDefault(false)

        // Makes an interrupted wipe resumable — force-stopping the app is one tap away in
        // Settings, and this runs while an attacker holds the device. commit(), before anything
        // is destroyed.
        val hostileLocationWasEnabled = markWipeInProgress(appContext, currentlyEnabled)

        // Captured BEFORE the sharedPrefs step deletes `push_pairing_secure`. The deregister runs
        // last (destroying plaintext must not wait on the network) but authenticates with a
        // credential that step removes, so it has to be read now.
        val pairingForDeregister = runCatching { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }
            .onFailure { android.util.Log.w(TAG, "Could not read the pairing before wiping; deregister will be skipped", it) }
            .getOrNull()

        // ORDER IS THE POINT: local plaintext first, network last. An attacker holding the device
        // can force-stop the app at any moment, so every step that blocks — above all the ~20s of
        // OkHttp timeouts in the deregister — has to come after the destruction, not before it.
        //
        // Leads because it needs no I/O and AppRestart relaunches into the same JVM: an uncleared
        // draft is restorable from the compose screen in the attacker's session.
        step("inMemoryPlaintext") {
            val unclearedHolders = InMemoryPlaintext.clearAll()
            if (unclearedHolders.isNotEmpty()) {
                throw IOException("Process-scoped plaintext holders failed to clear: $unclearedHolders")
            }
        }
        step("database") { closeAndDeleteDatabase(appContext) }
        step("datastores") {
            // Checked, like every other step. Discarding `delete()`'s result meant this step could
            // not fail however badly it went — in a routine whose whole contract is that nothing
            // silently succeeds — and `push_state` holds the last 30 sender/subject pairs.
            val undeleted = DATASTORE_NAMES.map { name ->
                name to File(appContext.filesDir, "datastore/$name.preferences_pb")
            }.filter { (_, file) -> file.exists() && !file.delete() }
            if (undeleted.isNotEmpty()) {
                throw IOException("Failed to delete datastores: ${undeleted.map { it.first }}")
            }
        }

        // Local push teardown BEFORE the network call: the connector's SQLite database holds the
        // WebPush ECDH private key, and none of this needs the network, so none of it belongs
        // behind something that does.
        step("cancelNotifications") {
            // A mail notification posted while unlocked keeps sender and subject in the shade after
            // the wipe, readable with no forensics at all.
            appContext.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }
        // UNREGISTER FIRST, THEN DELETE THE CONNECTOR'S STATE — reversed, the unregister has no
        // registration records left to unsubscribe with and the device stays subscribed.
        step("unifiedPushUnregister") { org.kysecurity.mail.push.UnifiedPushRegistrar.unregister(appContext) }
        step("unifiedPushDatabase") {
            // Lives in our sandbox but is not ours to name elsewhere. Holds the WebPush ECDH
            // private key and auth secret.
            appContext.deleteDatabase("unifiedpush-connector")
        }
        step("unifiedPushPrefs") {
            // Explicit: `UnifiedPush.unregister` deliberately keeps the distributor selection for a
            // later re-register, so nothing else removes the record of which distributor this user
            // runs.
            if (!appContext.deleteSharedPreferences("unifiedpush.connector")) {
                // Absent is the normal case (UnifiedPush was never selected); only a file that is
                // there and will not go is a failure.
                val file = File(File(appContext.dataDir, "shared_prefs"), "unifiedpush.connector.xml")
                if (file.exists()) throw IOException("Failed to delete unifiedpush.connector preferences")
            }
        }
        step("downloadedAttachments") {
            // Outside the sandbox, so no sandbox deletion reaches them — but this routine tells the
            // user their local data has been erased, and it has to be true of these too.
            DownloadedAttachmentLedger.deleteAll(appContext)
        }
        // Before the sharedPrefs sweep below, so the vault deletes its own file rather than having
        // it removed underneath it and then recreated — EncryptedSharedPreferences.create rebuilds
        // both the file and a Tink keyset the moment it is touched.
        //
        // No state-report worker on this path: the wipe deregisters and clears the pairing, so the
        // device row goes away server-side and there is nothing left to correct.
        step("enrollmentTeardown") {
            // A named step so a failure lands in the incomplete-wipe list. It has to throw to get
            // there: `step` records a failure only when its body does, and a key surviving a wipe
            // nobody chose is exactly what the incomplete result exists to tell the user about.
            val leftBehind = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(appContext)
            check(leftBehind.isEmpty()) { "enrollment teardown left $leftBehind" }
        }
        // Same shape and same reason as enrollmentTeardown above: the sharedPrefs sweep removes the
        // sealed blob but not the Keystore alias, and a key surviving a wipe nobody chose is exactly
        // what the incomplete result exists to report.
        step("biometricUnlockVault") {
            val leftBehind = BiometricUnlockVault(appContext).destroy()
            check(leftBehind.isEmpty()) { "biometric unlock vault left $leftBehind" }
        }
        // Same again for the MFA approval screen's gate key. It seals nothing, so what survives is
        // only an alias — but a Keystore entry outliving a wipe is exactly what the incomplete
        // result exists to report, whatever it holds.
        step("authGateKey") {
            val leftBehind = AuthGateKey.destroy()
            check(leftBehind.isEmpty()) { "auth gate key left $leftBehind" }
        }
        // The database is encrypted at rest, so it is only as destroyed as its key. `database`
        // above deletes the file and reports if it could not; this makes any surviving copy of the
        // file unreadable as well, which is the property that matters when the file delete is the
        // step most likely to fail. Runs AFTER `database`, so the delete is not attempted against a
        // database whose key has already gone.
        step("databaseKey") {
            val leftBehind = DatabaseKey.destroy(appContext)
            check(leftBehind.isEmpty()) { "database key left $leftBehind" }
        }
        step("pullWorker") { org.kysecurity.mail.push.PullScheduler.cancelPeriodic(appContext) }
        step("deviceContactWorker") { org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(appContext) }

        // After the connector teardown above, which needs `unifiedpush.connector` to still hold the
        // distributor selection that `UnifiedPush.unregister` reads.
        step("sharedPrefs") { deleteAllSharedPrefs(appContext) }
        step("webViewState") { clearWebViewState(appContext) }
        step("deviceContactRows") { deleteSyncedDeviceContactRows(appContext) }
        step("deviceContactAccount") { DeviceContactAccountManager(appContext).removeAccountBlocking() }

        // Clears the in-memory pairing StateFlow so anything still holding the graph sees "not
        // paired" rather than a stale pairing read before the file was deleted. The deregister
        // below authenticates with `pairingForDeregister`, captured before any of this ran, so
        // clearing here does not disarm it.
        step("clearPairingState") { PushRuntime.graph(appContext).repository.clearPairing() }

        step("appLock") {
            // Reports rather than merely resets: the tripwire's durable half is a Keystore alias,
            // and an alias outliving a wipe is exactly what the incomplete result exists to name.
            val leftBehind = AppLockStore(appContext).resetReportingLeftovers()
            check(leftBehind.isEmpty()) { "app lock teardown left $leftBehind" }
        }

        // Re-assert the protection posture the deletions above erased. Runs after the sharedPrefs
        // step on purpose — writing it earlier would just be deleted again. A step, not a bare
        // call, so a failure to restore it is reported rather than leaving the user believing
        // protection survived. Nothing is re-enabled that was not already on.
        if (hostileLocationWasEnabled) {
            step("restoreHostileLocationProtection") { HostileLocationSettings(appContext).setEnabled(true) }
        }

        // ─── Everything below this line touches the network. Nothing below it destroys local
        // data, so an attacker who force-stops the app here has already lost. ───

        // The FCM teardown is NETWORK, and it belongs here rather than up among the local steps.
        // Above, it sat before the sharedPrefs sweep, the OS contacts purge and the app-lock reset —
        // so an attacker holding the device only had to put it on a network that black-holes packets
        // (rather than refusing them), wait for Play Services to hang, and force-stop the app from
        // Settings. Everything below the hang survived. That is precisely the ordering the banner
        // above forbids, and this step was the exception to it.
        //
        // withTimeoutOrNull DOES bound these, unlike the deregister: `Task.await()` suspends on a
        // callback rather than blocking a thread in a socket read, so cancelling the continuation
        // actually stops the wait. It runs inside NonCancellable, whose children are still
        // cancellable by their own timeout.
        step("fcmToken") {
            val settled = withTimeoutOrNull(FCM_TEARDOWN_TIMEOUT_MS) {
                com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken().await()
                // The token is not the installation. Leaving the Fid behind keeps this device
                // linkable across the wipe and a later re-pair.
                com.google.firebase.installations.FirebaseInstallations.getInstance().delete().await()
            }
            if (settled == null) throw IOException("FCM teardown did not finish within ${FCM_TEARDOWN_TIMEOUT_MS}ms")
        }

        // Network LAST, bounded by the client's own `callTimeout` — coroutine cancellation cannot
        // interrupt a thread blocked in a socket read, so `withTimeoutOrNull` here would only skip
        // whatever came after it.
        //
        // Deliberately NOT folded into `failed`: [WipeResult.Incomplete] means "local data may
        // still be on disk", and an unreachable relay says nothing about local data — every byte of
        // which is gone by this line.
        val deregistered = runCatching {
            PushRuntime.graph(appContext).repository
                .unpairDevice(PushRuntime.graph(appContext).deregisterClient, pairingForDeregister)
        }.getOrElse { org.kysecurity.mail.push.DeregisterResult.Error(it.message ?: "deregister threw") }
        if (deregistered is org.kysecurity.mail.push.DeregisterResult.Error) {
            android.util.Log.e(
                TAG,
                "Local wipe finished but server deregistration failed (${deregistered.message}); " +
                    "the relay may keep pushing to this device until it is removed server-side",
            )
        }

        if (failed.isEmpty()) {
            clearWipeMarker(appContext)
            WipeResult.Complete
        } else {
            android.util.Log.e(TAG, "WIPE INCOMPLETE — failed steps: $failed")
            // Past the ceiling, stop asking the app to re-wipe itself at every launch — that was a
            // brick, and it is why the ceiling exists. What must NOT happen alongside it is
            // clearing the marker: deletion failed, so the app has to keep knowing that. Fail
            // closed instead — [KEY_WIPE_ABANDONED] ends the automatic retries, the marker and the
            // failed step names persist, and [enforceTripwire] reports the same permanent
            // "incomplete, manual recovery required" verdict on every launch from here on.
            val givingUp = wipeAttempts(appContext) >= MAX_WIPE_RESUMES
            if (givingUp) {
                android.util.Log.e(TAG, "Wipe failed $MAX_WIPE_RESUMES times; giving up on resuming it")
            }
            recordFailedSteps(appContext, failed, abandoned = givingUp)
            WipeResult.Incomplete(failed, willRetry = !givingUp)
        }
    }

    /** Whether a previously started wipe never reached the end — see [wipeAndResetApp]. */
    fun wipeInterrupted(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_WIPE_IN_PROGRESS, false)

    private fun wipeAttempts(appContext: Context): Int =
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).getInt(KEY_WIPE_ATTEMPTS, 0)

    /**
     * The terminal state described in [KEY_WIPE_ABANDONED], or null while the wipe is still being
     * resumed (or has never run).
     *
     * Public so a screen can ask directly rather than inferring it from a bare `wipeInterrupted`,
     * which is true of both a resumable wipe and an abandoned one and means opposite things.
     */
    fun abandonedWipe(context: Context): WipeResult.Incomplete? {
        val prefs = context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_WIPE_ABANDONED, false)) return null
        val steps = prefs.getStringSet(KEY_WIPE_FAILED_STEPS, emptySet()).orEmpty().sorted()
        return WipeResult.Incomplete(steps, willRetry = false)
    }

    /**
     * "Refuse to do anything at all", for the non-Activity entry points that cannot go through
     * [LockedActivity]'s terminal block. The pairing credential is often among what survived an
     * abandoned wipe, so push, lock-screen previews and MFA approval all stay reachable otherwise.
     *
     * One boolean from SharedPreferences: no graph, no coroutine, no Keystore, and independent of
     * [startupVerdict], which may not be complete when a push arrives.
     */
    fun blockedByAbandonedWipe(context: Context): Boolean = abandonedWipe(context) != null

    /** Persists what this run could not destroy, in the retained wipe-state file, alongside whether
     *  the app has stopped resuming it. `commit()` because the process may be killed at any point
     *  during a wipe — that is the whole premise of the marker. */
    private fun recordFailedSteps(appContext: Context, failed: List<String>, abandoned: Boolean) {
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_WIPE_FAILED_STEPS, failed.toSet())
            .putBoolean(KEY_WIPE_ABANDONED, abandoned)
            .commit()
    }

    /**
     * Marker, attempt count and protection posture in one `commit()`, before anything is destroyed.
     * Returns the posture the *first* run observed — sticky across resumes, because a resumed run
     * would otherwise read the settings file an interrupted run already deleted.
     */
    private fun markWipeInProgress(appContext: Context, hostileLocationEnabled: Boolean): Boolean {
        val prefs = appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        val alreadyRecorded = prefs.getBoolean(KEY_HOSTILE_LOCATION_WAS_ENABLED, false)
        val posture = hostileLocationEnabled || alreadyRecorded
        // The attempt counter belongs to ONE wipe episode, not to the install: a new episode gets
        // the full budget, or an install-lifetime counter would be spent before the wipe that
        // matters. An abandoned episode is over even though its marker is still set.
        val resuming = prefs.getBoolean(KEY_WIPE_IN_PROGRESS, false) &&
            !prefs.getBoolean(KEY_WIPE_ABANDONED, false)
        val attempts = if (resuming) prefs.getInt(KEY_WIPE_ATTEMPTS, 0) + 1 else 1
        prefs.edit()
            .putBoolean(KEY_WIPE_IN_PROGRESS, true)
            .putBoolean(KEY_HOSTILE_LOCATION_WAS_ENABLED, posture)
            .putInt(KEY_WIPE_ATTEMPTS, attempts)
            .putBoolean(KEY_WIPE_ABANDONED, false)
            .commit()
        return posture
    }

    /**
     * Ends this wipe, **keeping** [KEY_WIPE_ATTEMPTS]. `clear()` would drop it, so reaching
     * [MAX_WIPE_RESUMES] would reset the budget and the ceiling would bound nothing. The count is
     * reset only by [markWipeInProgress], at episode start.
     */
    private fun clearWipeMarker(appContext: Context) {
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_WIPE_IN_PROGRESS)
            .remove(KEY_HOSTILE_LOCATION_WAS_ENABLED)
            // Only ever reached from the clean-run branch, which is the one place these may go:
            // they record that destruction is still owed.
            .remove(KEY_WIPE_ABANDONED)
            .remove(KEY_WIPE_FAILED_STEPS)
            .commit()
    }

    /**
     * Closes and deletes the database (plus its journal files) and drops [DataRuntime], so the next
     * access rebuilds rather than being handed the closed instance.
     *
     * Shared with Hostile Location Protection's toggle: enabling it must delete any on-disk cache
     * written before it was turned on.
     */
    suspend fun closeAndDeleteDatabase(context: Context) = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext

        // ORDER MATTERS. Quiesce first, or closing the database out from under an in-flight pool
        // thread is an uncaught exception on a non-UI thread — a process kill. Then `take()`, not
        // `invalidate()` + `graph()`: the latter builds a new database and closes *that*.
        val settled = org.kysecurity.mail.MailBackgroundExecutor.quiesce()
        val doomed = DataRuntime.takeGraph()
        runCatching { doomed?.database?.close() }
            .onFailure { android.util.Log.e(TAG, "Failed to close the database before deleting it", it) }
        val deleted = appContext.deleteDatabase(org.kysecurity.mail.data.DATABASE_NAME)
        // Reported, not merely logged. `deleteDatabase` returns false when the file is still there,
        // which after an unquiesced teardown is exactly what "mail work is still holding it open"
        // looks like — and the cached message bodies are the single most sensitive thing a wipe is
        // supposed to destroy. The quiesce result is folded in so the cause is named rather than
        // guessed at from a bare "false".
        if (!deleted && appContext.getDatabasePath(org.kysecurity.mail.data.DATABASE_NAME).exists()) {
            throw IOException(
                "${org.kysecurity.mail.data.DATABASE_NAME} still exists after deletion" +
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
     * Clears Chromium's per-application profile. "Show images" makes the mail WebView fetch for
     * real, after which cookies, HSTS and alt-svc state under `app_webview` are a host-level record
     * of the servers contacted while reading mail.
     *
     * Nothing here is caught — a failure has to reach [wipeAndResetApp]'s `failed` list. The
     * WebView statics must run on Main; this is called from `Dispatchers.IO`.
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

        // Child by child, and logged rather than thrown: this runs in a live process where OkHttp,
        // WebView and ART are still creating files underneath, so a partial delete is routine and
        // must not brick the wipe. Nothing security-relevant is unique to these directories.
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
     * `CALLER_IS_SYNCADAPTER` makes the delete immediate rather than a tombstone, which would keep
     * the data until a sync that will never happen for an account we are about to remove.
     *
     * Throws on failure, and is its own step, because this is the one thing a wipe destroys that
     * lives **outside this app's sandbox**.
     */
    private fun deleteSyncedDeviceContactRows(context: Context) {
        // Shared with the unpair path via DeviceContactPurge, which does the provider delete without
        // constructing any graph — building DeviceContactsGraph here would rebuild the database this
        // wipe has already deleted.
        val deleted = org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context)
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
     */
    suspend fun enforceTripwire(context: Context): WipeResult? {
        val appContext = context.applicationContext

        // A wipe that started and never finished is resumed before anything else, including the
        // tripwire check itself — the interrupted run may have deleted the app-lock state that
        // tripwireBroken() reads, so relying on the tripwire alone would let the rest of the wipe
        // stay undone forever. Re-running is safe: every step is idempotent.
        // Checked before the resume, and never cleared by anything but a clean run: past
        // MAX_WIPE_RESUMES the app stops re-running the destructive pass, but it does not stop
        // knowing that data may still be here. Every launch from now on lands on
        // `security_wipe_incomplete_final_notice` instead of a first-run screen that implies the
        // erasure succeeded.
        abandonedWipe(appContext)?.let {
            android.util.Log.e(TAG, "Previous wipe was abandoned with steps still failing: ${it.failedSteps}")
            return it
        }

        if (wipeInterrupted(appContext)) {
            android.util.Log.e(TAG, "Previous wipe did not complete; resuming")
            return wipeAndResetApp(appContext)
        }

        if (!AppLockStore(appContext).tripwireBroken()) return null
        android.util.Log.e(TAG, "App-lock state vanished while a lock was configured; wiping")
        return wipeAndResetApp(appContext)
    }

    /**
     * Completes once the startup tripwire check has finished, carrying whether it wiped.
     *
     * The check is a **gate**: `Application.onCreate` returns before the launcher Activity starts,
     * so it cannot promise to run first. [LockedActivity] awaits this before rendering anything.
     */
    val startupVerdict: kotlinx.coroutines.CompletableDeferred<WipeResult?> =
        kotlinx.coroutines.CompletableDeferred()
}
