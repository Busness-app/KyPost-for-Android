package org.kysecurity.mail.push

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import org.kysecurity.mail.ScopedValue
import org.kysecurity.mail.security.AppLockStore
import org.kysecurity.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.tasks.await
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException

private val Context.pushDataStore by preferencesDataStore(name = "push_state")

private val KEY_LAST_SYNC_AT = longPreferencesKey("sync_last_at")
private val KEY_SYNC_ERROR = stringPreferencesKey("sync_error")
private val KEY_HISTORY_JSON = stringPreferencesKey("history_json")
private val KEY_DELIVERY_MODE = stringPreferencesKey("delivery_mode")
private val KEY_PULL_ENDPOINT = stringPreferencesKey("pull_endpoint")
private val KEY_PULL_CURSOR = longPreferencesKey("pull_cursor")
private val KEY_PULL_CURSOR_SUB = stringPreferencesKey("pull_cursor_sub")
private val KEY_TRANSPORT = stringPreferencesKey("transport")
private val KEY_UNIFIEDPUSH_ENDPOINT = stringPreferencesKey("unifiedpush_endpoint")
private val KEY_UNIFIEDPUSH_P256DH = stringPreferencesKey("unifiedpush_p256dh")
private val KEY_UNIFIEDPUSH_AUTH = stringPreferencesKey("unifiedpush_auth")

private const val HISTORY_LIMIT = 30

private const val TAG = "PushRepository"

class PushRepository(
    private val context: Context,
    // Injected: PushGraph owns the single instance that holds the pairing StateFlow.
    private val securePairingStore: SecurePairingStore = SecurePairingStore(context),
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val hostileLocationSettings = SecurityRuntime.graph(context).hostileLocationSettings
    private val pullCursorValue = ScopedValue(
        dataStore = context.pushDataStore,
        scopeKey = KEY_PULL_CURSOR_SUB,
        valueKey = KEY_PULL_CURSOR,
    )

    /** Push history while Hostile Location Protection is on: nothing may touch disk. */
    private val inMemoryHistory = MutableStateFlow<List<PushPayload>>(emptyList())

    val state: Flow<PushState> = combine(
        context.pushDataStore.data.catch { ex ->
            if (ex is IOException) emit(emptyPreferences()) else throw ex
        },
        securePairingStore.pairing,
        inMemoryHistory,
    ) { prefs, pairing, volatileHistory -> toState(prefs, pairing, volatileHistory) }

    /** Whether a pairing exists right now, read straight from the store — for cold-path callers. */
    fun isPairedNow(): Boolean = securePairingStore.pairing.value != null

    fun pairingForAuthenticatedCall(): PairingData? =
        securePairingStore.pairingSnapshot(SecurityRuntime.graph(context).appLockManager.cachedCredentialKeys())

    /** For [MfaApprovalActivity]: the app is legitimately still locked when the decision is sent. */
    fun pairingForAuthenticatedCall(keys: org.kysecurity.mail.security.CredentialKeys?): PairingData? =
        securePairingStore.pairingSnapshot(keys)

    /** The TOFU TLS pin with its host, or null. Read fresh — it changes on re-pairing. */
    fun currentTlsPin(): TlsPin? = securePairingStore.currentTlsPin()

    /** See [SecurePairingStore.tlsPinState] — distinguishes "never pinned" from "pin lost". */
    fun tlsPinState(): TlsPinState = securePairingStore.tlsPinState()

    /** See [SecurePairingStore.tlsPinIsLeafOnly] — false means a legacy whole-chain set is stored. */
    fun tlsPinIsLeafOnly(): Boolean = securePairingStore.tlsPinIsLeafOnly()

    /** Persist the TLS pin captured on a just-succeeded pairing call. Only
     *  [PushSyncCoordinator.attemptPairing] calls this, not every routine registration resync. */
    suspend fun saveTlsPin(pin: TlsPin) = securePairingStore.saveTlsPin(pin)

    /** True when the stored `deviceSecret` still needs wrapping (or re-wrapping) under the current
     *  credential-key scheme; see [SecurePairingStore.needsCredentialRewrap]. */
    fun needsCredentialRewrap(): Boolean = securePairingStore.needsCredentialRewrap()

    /** Captured before the network call and reused after: the app can lock in between. */
    sealed class PairingCredentialState {
        /** The credential gate is off: secrets are stored as they arrive. */
        object NotGated : PairingCredentialState()

        /** Not a `data class`: identity `equals`/`hashCode` over [salt] behind a promise of
         *  structural equality. Only ever matched with `is`. Enforced by `SourceRulesTest`. */
        class Available(
            val keys: org.kysecurity.mail.security.CredentialKeys,
            val salt: ByteArray,
        ) : PairingCredentialState()

        /** The gate is on and no PIN-derived key exists here — nothing may be wrapped, and nothing
         *  that is already stored may be replaced. */
        object Unavailable : PairingCredentialState()
    }

    /** Callers about to mint a secret must take this first and hand it back to [savePairing]. */
    fun currentCredentialState(): PairingCredentialState {
        val securityGraph = SecurityRuntime.graph(context)
        if (!securityGraph.appLockStore.isCredentialPinGateEnabled()) return PairingCredentialState.NotGated
        val keys = securityGraph.appLockManager.cachedCredentialKeys() ?: return PairingCredentialState.Unavailable
        val salt = securityGraph.appLockStore.credentialSalt() ?: return PairingCredentialState.Unavailable
        return PairingCredentialState.Available(keys, salt)
    }

    /** Saves pairing data, wrapping `deviceSecret` when the credential gate is on. */
    suspend fun savePairing(
        pairing: PairingData,
        credentialState: PairingCredentialState = currentCredentialState(),
    ) {
        when (credentialState) {
            is PairingCredentialState.Available ->
                securePairingStore.savePairing(
                    pairing,
                    gateEnabled = true,
                    credentialKeys = credentialState.keys,
                    credentialSalt = credentialState.salt,
                )
            is PairingCredentialState.Unavailable -> {
                if (!pairing.deviceSecret.isNullOrBlank()) {
                    android.util.Log.e(
                        TAG,
                        "Refusing to store a device secret with the credential gate on and no PIN-derived key; " +
                            "the caller should have taken currentCredentialState() before registering",
                    )
                }
                securePairingStore.savePairing(pairing, SecretWrite.Preserve)
            }
            is PairingCredentialState.NotGated ->
                securePairingStore.savePairing(pairing, gateEnabled = false)
        }
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_SYNC_ERROR)
        }
    }

    /** Drops everything scoped to the account we are leaving; no table carries a subscriber column. */
    private suspend fun purgeAccountScopedData() {
        // The OS contact rows go FIRST, while the link table that indexes them still exists.
        // DeviceContactPurge, not the graph: building that graph rebuilds the database during a wipe.
        if (org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context) < 0) {
            android.util.Log.e(TAG, "Could not delete this app's raw contacts on unpair; they may remain")
        }
        runCatching {
            val accounts = org.kysecurity.mail.contacts.device.DeviceContactAccountManager(context)
            if (accounts.accountExists() && !accounts.removeAccountBlocking()) {
                android.util.Log.e(TAG, "Could not remove the device contacts account on unpair; its rows may remain")
            }
        }.onFailure { android.util.Log.e(TAG, "Failed to remove the device contacts account", it) }
        runCatching { org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(context) }
            .onFailure { android.util.Log.e(TAG, "Failed to cancel the device contact worker", it) }

        runCatching {
            // peek, not graph: building one during a wipe recreates the database, disk-backed.
            val db = org.kysecurity.mail.data.DataRuntime.peekGraph()?.database
            if (db != null) {
                db.emailDao().clearAll()
                db.contactDao().clearAll()
                db.pendingContactChangeDao().clearAll()
                db.groupDao().clearAll()
                db.groupLinkDao().clearAll()
                db.deviceContactLinkDao().deleteAll()
                // The contact-sync cursor lives here now; without this a re-pair resumes from the old cursor.
                db.contactSyncStateDao().clearAll()
            }
        }.onFailure {
            android.util.Log.e(TAG, "Failed to purge account-scoped tables", it)
        }
        // Device-contact sync gates only on its own toggle and Hostile Location Protection, never
        // on having a pairing, so it has to be switched off explicitly here.
        runCatching { org.kysecurity.mail.contacts.device.DeviceContactSyncSettings(context).setEnabled(false) }
            .onFailure { android.util.Log.e(TAG, "Failed to disable device contact sync", it) }
        runCatching { context.deleteSharedPreferences(org.kysecurity.mail.KeywordSettings.PREFS_NAME) }
            .onFailure { android.util.Log.e(TAG, "Failed to delete keyword settings", it) }
        // Scoping makes a stale value unreadable, not absent — these files must actually be deleted.
        // contacts_state is legacy: kept in this list so older installs do not keep the old file.
        listOf("mail_sync_state", "contacts_state").forEach { name ->
            runCatching { java.io.File(context.filesDir, "datastore/$name.preferences_pb").delete() }
                .onFailure { android.util.Log.e(TAG, "Failed to delete datastore $name", it) }
        }
        // Every process-static holder at once via the registry, not by name — enumeration missed one.
        val enrollmentResidue = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(context)
        if (enrollmentResidue.isNotEmpty()) {
            android.util.Log.e(TAG, "Enrollment teardown left $enrollmentResidue behind while unpairing")
        }
        val uncleared = org.kysecurity.mail.InMemoryPlaintext.clearAll()
        if (uncleared.isNotEmpty()) {
            android.util.Log.e(TAG, "Failed to clear process-scoped state: $uncleared")
        }
    }

    /** Drops pairing proof and the TOFU pin, KEEPING account-scoped data.
     *
     *  Recovering from a rotated certificate or a stranded device secret is not a change of
     *  account, and must not cost the user their mail. [clearPairing] stays the destructive one,
     *  for a deliberate unpair and for [PushSyncCoordinator.attemptPairing]'s genuine
     *  account-replacement branch. Clearing the pin reopens the TOFU window so the next pairing
     *  can capture a fresh chain. */
    suspend fun resetPairingCredential() {
        securePairingStore.clearPairing()
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_SYNC_ERROR)
            prefs.remove(KEY_LAST_SYNC_AT)
            // Registration state that belongs to the credential being reset, not to the account.
            prefs.remove(KEY_TRANSPORT)
            prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT)
            prefs.remove(KEY_UNIFIEDPUSH_P256DH)
            prefs.remove(KEY_UNIFIEDPUSH_AUTH)
        }
    }

    suspend fun clearPairing() {
        purgeAccountScopedData()
        securePairingStore.clearPairing()
        inMemoryHistory.value = emptyList()
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_LAST_SYNC_AT)
            prefs.remove(KEY_SYNC_ERROR)
            prefs.remove(KEY_HISTORY_JSON)
            prefs.remove(KEY_DELIVERY_MODE)
            prefs.remove(KEY_PULL_ENDPOINT)
            prefs.remove(KEY_PULL_CURSOR)
            prefs.remove(KEY_PULL_CURSOR_SUB)
            prefs.remove(KEY_TRANSPORT)
            prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT)
            prefs.remove(KEY_UNIFIEDPUSH_P256DH)
            prefs.remove(KEY_UNIFIEDPUSH_AUTH)
        }
    }

    /** Best-effort deregister then unconditional clear; SecurityWipe passes a pre-captured pairing. */
    suspend fun unpairDevice(
        deregisterClient: DeregisterClient,
        pairing: PairingData? = pairingForAuthenticatedCall(),
    ): DeregisterResult {
        val networkResult = if (pairing != null) {
            deregisterClient.deregister(pairing)
        } else {
            DeregisterResult.Error("Device is not paired")
        }
        tearDownPushTransport()
        clearPairing()
        PullScheduler.cancelPeriodic(context)
        return networkResult
    }

    /** Severs the delivery channel itself. Not called from [PushSyncCoordinator]'s replacement path. */
    private suspend fun tearDownPushTransport() {
        runCatching {
            context.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }
        // Unregister before deleting the connector's state, or the device stays subscribed.
        runCatching { UnifiedPushRegistrar.unregister(context) }
        // Holds the WebPush ECDH private key and auth secret.
        runCatching { context.deleteDatabase("unifiedpush-connector") }
        // UnifiedPush.unregister keeps the distributor selection on purpose so a later re-register
        // reuses it; after an unpair that record should not outlive the pairing.
        runCatching { context.deleteSharedPreferences("unifiedpush.connector") }
        runCatching {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().deleteToken().await()
            // Rotating the messaging token leaves the Firebase installation and its stable Fid in
            // place, which keeps the device linkable across an unpair and a later re-pair.
            com.google.firebase.installations.FirebaseInstallations.getInstance().delete().await()
        }
    }

    /** Persist the authoritative delivery mode and (derived or server-provided) pull endpoint. */
    suspend fun updateDelivery(mode: DeliveryMode, pullEndpoint: String?) {
        context.pushDataStore.edit { prefs ->
            prefs[KEY_DELIVERY_MODE] = mode.wire
            if (pullEndpoint.isNullOrBlank()) prefs.remove(KEY_PULL_ENDPOINT) else prefs[KEY_PULL_ENDPOINT] = pullEndpoint
        }
    }

    /** Persist the transport the server confirmed for the last successful registration. */
    suspend fun updateTransport(transport: PushTransport?) {
        context.pushDataStore.edit { prefs ->
            if (transport == null) prefs.remove(KEY_TRANSPORT) else prefs[KEY_TRANSPORT] = transport.wire
        }
    }

    /** Persisted so a resync can resend them; they only ever arrive via onNewEndpoint. Null clears. */
    suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?) {
        context.pushDataStore.edit { prefs ->
            if (endpoint.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT) else prefs[KEY_UNIFIEDPUSH_ENDPOINT] = endpoint
            if (p256dh.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_P256DH) else prefs[KEY_UNIFIEDPUSH_P256DH] = p256dh
            if (auth.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_AUTH) else prefs[KEY_UNIFIEDPUSH_AUTH] = auth
        }
    }

    /** The durable pull cursor for [subscriberId], scoped so a new subscriber starts clean. */
    suspend fun pullCursor(subscriberId: String): Long = pullCursorValue.get(subscriberId) ?: 0L

    /** Advance the cursor to max(existing, [cursor]); resets when the subscriber changes. */
    suspend fun advancePullCursor(subscriberId: String, cursor: Long) {
        pullCursorValue.update(subscriberId) { current -> maxOf(current ?: 0L, cursor) }
    }

    suspend fun updateSyncState(lastSyncAtEpochMs: Long?, syncError: String?) {
        context.pushDataStore.edit { prefs ->
            if (lastSyncAtEpochMs == null) prefs.remove(KEY_LAST_SYNC_AT) else prefs[KEY_LAST_SYNC_AT] = lastSyncAtEpochMs
            if (syncError.isNullOrBlank()) prefs.remove(KEY_SYNC_ERROR) else prefs[KEY_SYNC_ERROR] = syncError
        }
    }

    suspend fun appendPayload(payload: PushPayload) {
        if (hostileLocationSettings.isEnabled()) {
            inMemoryHistory.update { current -> (listOf(payload) + current).distinctBy { it.messageId }.take(HISTORY_LIMIT) }
            return
        }
        context.pushDataStore.edit { prefs ->
            val current = decodeHistory(prefs[KEY_HISTORY_JSON])
            val updated = (listOf(payload) + current)
                .distinctBy { it.messageId }
                .take(HISTORY_LIMIT)
            prefs[KEY_HISTORY_JSON] = json.encodeToString(updated)
        }
    }

    private fun toState(prefs: Preferences, pairing: PairingData?, volatileHistory: List<PushPayload>): PushState {
        val history = if (hostileLocationSettings.isEnabled()) volatileHistory else decodeHistory(prefs[KEY_HISTORY_JSON])
        val pullEndpoint = prefs[KEY_PULL_ENDPOINT]
            ?: pairing?.serverUrl?.let { resolvePullEndpoint(it, null) }
        return PushState(
            pairing = pairing,
            lastTokenSyncAtEpochMs = prefs[KEY_LAST_SYNC_AT],
            syncError = prefs[KEY_SYNC_ERROR],
            history = history,
            latestPayload = history.firstOrNull(),
            deliveryMode = DeliveryMode.fromWire(prefs[KEY_DELIVERY_MODE]),
            pullEndpoint = pullEndpoint,
            transport = PushTransport.fromWire(prefs[KEY_TRANSPORT]),
            unifiedPushEndpoint = prefs[KEY_UNIFIEDPUSH_ENDPOINT],
            unifiedPushP256dh = prefs[KEY_UNIFIEDPUSH_P256DH],
            unifiedPushAuth = prefs[KEY_UNIFIEDPUSH_AUTH],
        )
    }

    private fun decodeHistory(value: String?): List<PushPayload> {
        if (value.isNullOrBlank()) return emptyList()
        return runCatching { json.decodeFromString<List<PushPayload>>(value) }
            .onFailure { android.util.Log.w(TAG, "Dropping unreadable push history", it) }
            .getOrDefault(emptyList())
    }
}

data class PushState(
    val pairing: PairingData?,
    val lastTokenSyncAtEpochMs: Long?,
    val syncError: String?,
    val latestPayload: PushPayload?,
    val history: List<PushPayload>,
    val deliveryMode: DeliveryMode = DeliveryMode.PUSH,
    val pullEndpoint: String? = null,
    val transport: PushTransport? = null,
    val unifiedPushEndpoint: String? = null,
    val unifiedPushP256dh: String? = null,
    val unifiedPushAuth: String? = null,
)
