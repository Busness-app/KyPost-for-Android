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

/** DataStore has no delete API, so the backing files go directly; a wipe always relaunches. */
private val DATASTORE_NAMES = listOf("push_state", "contacts_state", "mail_sync_state")

/** Retained because a later step still needs them: ordering, the wipe marker and the ledger. */
private val PREFS_NAMES_RETAINED = setOf(
    "app_lock_secure",
    "app_lock_tripwire",
    "org.kysecurity.mail.wipe_state",
    "unifiedpush.connector",
    DownloadedAttachmentLedger.PREFS_NAME,
)

/** Plaintext mail metadata, no credentials; shared by the full wipe and the HLP enable path. */
private val METADATA_PREFS_NAMES = listOf(org.kysecurity.mail.KeywordSettings.PREFS_NAME)

/** Listed in [PREFS_NAMES_RETAINED]: the wipe's own progress marker must outlive the wipe's own
 *  deletions, or an interruption erases the evidence that a wipe was ever started. */
private const val WIPE_STATE_PREFS = "org.kysecurity.mail.wipe_state"
private const val KEY_WIPE_IN_PROGRESS = "wipe_in_progress"
private const val KEY_WIPE_ATTEMPTS = "wipe_attempts"

/** Set when the wipe gives up. Must NOT clear [KEY_WIPE_IN_PROGRESS]; that marker outlives it. */
private const val KEY_WIPE_ABANDONED = "wipe_abandoned"

/** The step names of the abandoned wipe, so the permanent state can name what was left behind on
 *  every later launch rather than only on the run that gave up. */
private const val KEY_WIPE_FAILED_STEPS = "wipe_failed_steps"

/** Captured at wipe start: the sweep deletes the flag's own file, so a resume reads it here. */
private const val KEY_HOSTILE_LOCATION_WAS_ENABLED = "hostile_location_was_enabled"

/** Enough to ride out a transient failure, few enough that a permanent one gets reported. */
private const val MAX_WIPE_RESUMES = 3

/** Short: a hostile network must not be able to hold the wipe open. */
private const val FCM_TEARDOWN_TIMEOUT_MS = 3_000L

/** Scoped to local destruction; the server deregister is logged, not reported here. */
sealed class WipeResult {
    object Complete : WipeResult()

    /** `willRetry = false` is terminal: gated screens stay blocked until a reinstall. */
    data class Incomplete(
        val failedSteps: List<String>,
        val willRetry: Boolean = true,
    ) : WipeResult()
}

/** Must never report [WipeResult.Complete] unless every step really ran. */
object SecurityWipe {
    private const val TAG = "SecurityWipe"

    /** [NonCancellable]: a half-finished wipe is worse than either outcome. */
    suspend fun wipeAndResetApp(context: Context): WipeResult = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext
        val failed = mutableListOf<String>()

        /** Records the failure in [failed]; no step below may catch its own exceptions. */
        suspend fun step(name: String, body: suspend () -> Unit) {
            runCatching { body() }.onFailure {
                failed += name
                android.util.Log.e(TAG, "Wipe step failed: $name", it)
            }
        }

        // Captured before destruction and restored after; a wipe must not downgrade posture.
        val currentlyEnabled = runCatching { HostileLocationSettings(appContext).isEnabled() }
            .onFailure { android.util.Log.e(TAG, "Could not read the protection flag before wiping", it) }
            .getOrDefault(false)

        // Makes an interrupted wipe resumable; commit(), before anything is destroyed.
        val hostileLocationWasEnabled = markWipeInProgress(appContext, currentlyEnabled)

        // Captured before sharedPrefs deletes the credential the deregister authenticates with.
        val pairingForDeregister = runCatching { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }
            .onFailure { android.util.Log.w(TAG, "Could not read the pairing before wiping; deregister will be skipped", it) }
            .getOrNull()

        // The pin too: cleared state reads NeverPaired, which would send this request unpinned.
        val pinForDeregister = runCatching { PushRuntime.graph(appContext).repository.currentTlsPin() }
            .onFailure { android.util.Log.w(TAG, "Could not read the TLS pin before wiping", it) }
            .getOrNull()

        // ORDER IS THE POINT: local plaintext first, network last. A force-stop must lose nothing.
        step("inMemoryPlaintext") {
            val unclearedHolders = InMemoryPlaintext.clearAll()
            if (unclearedHolders.isNotEmpty()) {
                throw IOException("Process-scoped plaintext holders failed to clear: $unclearedHolders")
            }
        }
        step("database") { closeAndDeleteDatabase(appContext) }
        step("datastores") {
            // Checked, like every other step: `push_state` holds 30 sender/subject pairs.
            val undeleted = DATASTORE_NAMES.map { name ->
                name to File(appContext.filesDir, "datastore/$name.preferences_pb")
            }.filter { (_, file) -> file.exists() && !file.delete() }
            if (undeleted.isNotEmpty()) {
                throw IOException("Failed to delete datastores: ${undeleted.map { it.first }}")
            }
        }

        // Local push teardown BEFORE the network call; the connector DB holds the WebPush key.
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
            // `UnifiedPush.unregister` keeps the distributor selection; nothing else removes it.
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
        // Before the sharedPrefs sweep: creating the store would recreate its file and keyset.
        step("enrollmentTeardown") {
            // A named step, so a surviving key lands in the incomplete-wipe list.
            val leftBehind = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(appContext)
            check(leftBehind.isEmpty()) { "enrollment teardown left $leftBehind" }
        }
        // The sweep removes the sealed blob but not the Keystore alias.
        step("biometricUnlockVault") {
            val leftBehind = BiometricUnlockVault(appContext).destroy()
            check(leftBehind.isEmpty()) { "biometric unlock vault left $leftBehind" }
        }
        // Same for the MFA gate key: a Keystore entry outliving a wipe must be reported.
        step("authGateKey") {
            val leftBehind = AuthGateKey.destroy()
            check(leftBehind.isEmpty()) { "auth gate key left $leftBehind" }
        }
        // An encrypted database is only as destroyed as its key. Runs AFTER `database`.
        step("databaseKey") {
            val leftBehind = DatabaseKey.destroy(appContext)
            check(leftBehind.isEmpty()) { "database key left $leftBehind" }
        }
        step("pullWorker") { org.kysecurity.mail.push.PullScheduler.cancelPeriodic(appContext) }
        step("deviceContactWorker") { org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(appContext) }

        // BEFORE the sharedPrefs sweep: clearPairing() writes, and would recreate the files.
        step("clearPairingState") { PushRuntime.graph(appContext).repository.clearPairing() }

        // After the connector teardown above, which needs `unifiedpush.connector` to still hold the
        // distributor selection that `UnifiedPush.unregister` reads.
        step("sharedPrefs") { deleteAllSharedPrefs(appContext) }
        step("webViewState") { clearWebViewState(appContext) }
        step("deviceContactRows") { deleteSyncedDeviceContactRows(appContext) }
        // Removing the account is what makes CP2 hard-delete the raw contacts under it.
        step("deviceContactAccount") {
            val accounts = DeviceContactAccountManager(appContext)
            if (accounts.accountExists() && !accounts.removeAccountBlocking()) {
                throw IOException("Could not remove the contacts sync account; its raw contacts remain")
            }
        }

        step("appLock") {
            // Reports rather than merely resets: the tripwire's durable half is a Keystore alias,
            // and an alias outliving a wipe is exactly what the incomplete result exists to name.
            val leftBehind = AppLockStore(appContext).resetReportingLeftovers()
            check(leftBehind.isEmpty()) { "app lock teardown left $leftBehind" }
        }

        // Re-assert the posture the deletions erased; after sharedPrefs or it is deleted again.
        if (hostileLocationWasEnabled) {
            step("restoreHostileLocationProtection") { HostileLocationSettings(appContext).setEnabled(true) }
        }

        // Everything below touches the network; nothing below it destroys local data.

        // Network, so it belongs below that line; withTimeoutOrNull does bound Task.await().
        step("fcmToken") {
            val settled = withTimeoutOrNull(FCM_TEARDOWN_TIMEOUT_MS) {
                com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken().await()
                // The token is not the installation. Leaving the Fid behind keeps this device
                // linkable across the wipe and a later re-pair.
                com.google.firebase.installations.FirebaseInstallations.getInstance().delete().await()
            }
            if (settled == null) throw IOException("FCM teardown did not finish within ${FCM_TEARDOWN_TIMEOUT_MS}ms")
        }

        // Network LAST, bounded by the client's own callTimeout; not folded into `failed`.
        val deregistered = runCatching {
            val client = pinnedDeregisterClient(pinForDeregister)
            if (client == null) {
                // Fail closed: no captured pin is TlsPinState.Lost, which must not be downgraded.
                org.kysecurity.mail.push.DeregisterResult.Error(
                    "no TLS pin was captured before the wipe; refusing to send the device secret unpinned",
                )
            } else {
                PushRuntime.graph(appContext).repository.unpairDevice(client, pairingForDeregister)
            }
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
            // Past the ceiling, stop auto-retrying — the marker and failed steps must persist.
            val givingUp = wipeAttempts(appContext) >= MAX_WIPE_RESUMES
            if (givingUp) {
                android.util.Log.e(TAG, "Wipe failed $MAX_WIPE_RESUMES times; giving up on resuming it")
            }
            recordFailedSteps(appContext, failed, abandoned = givingUp)
            WipeResult.Incomplete(failed, willRetry = !givingUp)
        }
    }

    /** Bound to a pin captured before deletion, since the state a factory would read is gone. */
    internal fun pinnedDeregisterClient(
        pin: org.kysecurity.mail.push.TlsPin?,
    ): org.kysecurity.mail.push.DeregisterClient? {
        if (pin == null) return null
        return org.kysecurity.mail.push.DeregisterClient(
            callFactory = org.kysecurity.mail.pairingHttpClient(
                posture = org.kysecurity.mail.PinPosture.Pinned(host = pin.host, spkiSha256 = pin.spkiSha256),
                callTimeoutMillis = org.kysecurity.mail.push.PushGraph.DEREGISTER_CALL_TIMEOUT_MS,
            ),
        )
    }

    /** Whether a previously started wipe never reached the end — see [wipeAndResetApp]. */
    fun wipeInterrupted(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_WIPE_IN_PROGRESS, false)

    private fun wipeAttempts(appContext: Context): Int =
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).getInt(KEY_WIPE_ATTEMPTS, 0)

    /** The terminal state, or null while the wipe is still resumable — the two mean opposites. */
    fun abandonedWipe(context: Context): WipeResult.Incomplete? {
        val prefs = context.applicationContext
            .getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_WIPE_ABANDONED, false)) return null
        val steps = prefs.getStringSet(KEY_WIPE_FAILED_STEPS, emptySet()).orEmpty().sorted()
        return WipeResult.Incomplete(steps, willRetry = false)
    }

    /** Refuse-everything check for non-Activity entry points; one boolean, no graph or Keystore. */
    fun blockedByAbandonedWipe(context: Context): Boolean = abandonedWipe(context) != null

    /** commit(): the process may be killed at any point during a wipe. */
    private fun recordFailedSteps(appContext: Context, failed: List<String>, abandoned: Boolean) {
        appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_WIPE_FAILED_STEPS, failed.toSet())
            .putBoolean(KEY_WIPE_ABANDONED, abandoned)
            .commit()
    }

    /** Returns the posture the first run observed, sticky across resumes. */
    private fun markWipeInProgress(appContext: Context, hostileLocationEnabled: Boolean): Boolean {
        val prefs = appContext.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE)
        val alreadyRecorded = prefs.getBoolean(KEY_HOSTILE_LOCATION_WAS_ENABLED, false)
        val posture = hostileLocationEnabled || alreadyRecorded
        // The attempt counter belongs to one wipe episode, not to the install.
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

    /** Keeps [KEY_WIPE_ATTEMPTS]: clear() would reset the budget and unbound the ceiling. */
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

    /** Drops [DataRuntime] too; shared with the Hostile Location Protection enable path. */
    suspend fun closeAndDeleteDatabase(context: Context) = withContext(Dispatchers.IO + NonCancellable) {
        val appContext = context.applicationContext

        // ORDER MATTERS: quiesce first, then take() — invalidate()+graph() would close a new DB.
        val settled = org.kysecurity.mail.MailBackgroundExecutor.quiesce()
        val doomed = DataRuntime.takeGraph()
        runCatching { doomed?.database?.close() }
            .onFailure { android.util.Log.e(TAG, "Failed to close the database before deleting it", it) }
        val deleted = appContext.deleteDatabase(org.kysecurity.mail.data.DATABASE_NAME)
        // Reported, not merely logged: a false return means the file is still there.
        if (!deleted && appContext.getDatabasePath(org.kysecurity.mail.data.DATABASE_NAME).exists()) {
            throw IOException(
                "${org.kysecurity.mail.data.DATABASE_NAME} still exists after deletion" +
                    if (!settled) " (mail work did not quiesce first)" else "",
            )
        }
    }

    /** Removes metadata written before Hostile Location Protection was turned on. */
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

    /** Throws on the first failure so [wipeAndResetApp] records the step as failed. */
    private fun deleteAllSharedPrefs(appContext: Context) {
        val dir = File(appContext.dataDir, "shared_prefs")
        // Null means the directory could not be enumerated, which is not "nothing here".
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

    /** Nothing is caught: failures must reach `failed`. WebView statics must run on Main. */
    private suspend fun clearWebViewState(appContext: Context) {
        withContext(Dispatchers.Main) {
            android.webkit.WebStorage.getInstance().deleteAllData()
            android.webkit.CookieManager.getInstance().removeAllCookies(null)
            android.webkit.CookieManager.getInstance().flush()
        }
        // app_webview holds the host-level record; deleteRecursively reports false, not throws.
        val profile = File(appContext.dataDir, "app_webview")
        if (profile.exists() && !profile.deleteRecursively()) {
            throw IOException("Failed to delete the WebView profile directory")
        }

        // Logged rather than thrown: files are still being created underneath in a live process.
        listOf(appContext.cacheDir, appContext.codeCacheDir).forEach { dir ->
            dir.listFiles().orEmpty().forEach { child ->
                if (!child.deleteRecursively()) {
                    android.util.Log.w(TAG, "Could not fully delete cache entry ${child.name}")
                }
            }
        }
    }

    /** CALLER_IS_SYNCADAPTER makes the delete immediate; these rows live outside the sandbox. */
    private fun deleteSyncedDeviceContactRows(context: Context) {
        // Via DeviceContactPurge: building a graph here would rebuild the deleted database.
        val deleted = org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context)
        // Negative means the rows could not be reached; zero is legitimate, not assumed.
        if (deleted < 0) {
            throw IOException("Contacts provider refused to delete this app's raw contacts")
        }
    }

    /** Fires when the encrypted app-lock file is empty while the marker says a lock was set. */
    suspend fun enforceTripwire(context: Context): WipeResult? {
        val appContext = context.applicationContext

        // Resume first: the interrupted run may have deleted the state tripwireBroken() reads.
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

    /** A gate: Application.onCreate cannot promise to run before the launcher Activity. */
    val startupVerdict: kotlinx.coroutines.CompletableDeferred<WipeResult?> =
        kotlinx.coroutines.CompletableDeferred()
}
