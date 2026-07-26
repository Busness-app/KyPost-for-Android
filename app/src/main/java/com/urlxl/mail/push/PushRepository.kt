package com.urlxl.mail.push

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.urlxl.mail.ScopedValue
import com.urlxl.mail.security.AppLockStore
import com.urlxl.mail.security.HostileLocationSettings
import com.urlxl.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
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

class PushRepository(
    private val context: Context,
    // Injected rather than constructed here: this store owns a StateFlow of the current pairing,
    // and four separate instances of it used to exist across the app, each with its own copy of
    // that flow. PushGraph now owns the single instance.
    private val securePairingStore: SecurePairingStore = SecurePairingStore(context),
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val hostileLocationSettings = HostileLocationSettings(context)
    private val pullCursorValue = ScopedValue(
        dataStore = context.pushDataStore,
        scopeKey = KEY_PULL_CURSOR_SUB,
        valueKey = KEY_PULL_CURSOR,
    )

    /**
     * Push history while Hostile Location Protection is on.
     *
     * The whole promise of that feature is that nothing touches disk — Room goes in-memory for it.
     * Push history was still being written to `push_state`, an unencrypted protobuf, carrying
     * `senderName` and `emailSubject` for the last 30 messages. That is precisely the metadata the
     * feature exists to keep off the device, so under protection it lives here and dies with the
     * process instead.
     */
    private val inMemoryHistory = MutableStateFlow<List<PushPayload>>(emptyList())

    val state: Flow<PushState> = combine(
        context.pushDataStore.data.catch { ex ->
            if (ex is IOException) emit(emptyPreferences()) else throw ex
        },
        securePairingStore.pairing,
        inMemoryHistory,
    ) { prefs, pairing, volatileHistory -> toState(prefs, pairing, volatileHistory) }

    /** Pairing data for making an authenticated relay call right now — `deviceSecret` comes back
     *  null if "require unlock to receive push/MFA" is on and the app isn't currently unlocked via
     *  PIN; callers already treat a blank/missing deviceSecret as an auth failure, so this fails
     *  the same way a real 401 would. */
    fun pairingForAuthenticatedCall(): PairingData? =
        securePairingStore.pairingSnapshot(SecurityRuntime.graph(context).appLockManager.cachedCredentialKeys())

    /** The TOFU TLS pin captured right after the first successful pairing, with the host it came
     *  from, or null if none has been captured yet. Read fresh on every call — never cached by the
     *  caller — since it can change on re-pairing. */
    fun currentTlsPin(): TlsPin? = securePairingStore.currentTlsPin()

    /** Persist the TLS pin captured on a just-succeeded pairing call. Only
     *  [PushSyncCoordinator.attemptPairing] calls this, not every routine registration resync. */
    suspend fun saveTlsPin(pin: TlsPin) = securePairingStore.saveTlsPin(pin)

    /** True when the stored `deviceSecret` still needs wrapping (or re-wrapping) under the current
     *  credential-key scheme; see [SecurePairingStore.needsCredentialRewrap]. */
    fun needsCredentialRewrap(): Boolean = securePairingStore.needsCredentialRewrap()

    /**
     * Saves pairing data, wrapping `deviceSecret` behind the PIN-derived credential key when the
     * credential gate is on.
     *
     * Both branches key off [AppLockStore.isCredentialPinGateEnabled] — the *policy* — not off
     * whether a key happens to be cached. Deciding on cache state alone was wrong in both
     * directions. Wrapping whenever a key was cached meant that disabling the gate (which left the
     * derived keys cached) and then re-pairing in the same session re-wrapped the secret behind a
     * gate that would never open again. And falling through to the plaintext branch whenever no key
     * was cached meant a pairing performed in a biometric-unlocked session silently stored the
     * secret unwrapped *permanently*: the gate then let background pull/push/MFA succeed while
     * locked, so the user had no reason to ever enter the PIN, and the repair that
     * [com.urlxl.mail.security.rewrapPairingIfNeeded] would have applied never ran.
     *
     * With the gate on and no key available we keep the pairing but drop the secret, leaving
     * [SecurePairingStore.needsCredentialRewrap] true so the next PIN unlock restores it.
     */
    suspend fun savePairing(pairing: PairingData) {
        val gateEnabled = AppLockStore(context).isCredentialPinGateEnabled()
        val credentialKeys = SecurityRuntime.graph(context).appLockManager.cachedCredentialKeys()
        val credentialSalt = if (credentialKeys != null) AppLockStore(context).credentialSalt() else null
        when {
            gateEnabled && credentialKeys != null && credentialSalt != null ->
                securePairingStore.savePairing(pairing, credentialKeys, credentialSalt)
            gateEnabled ->
                securePairingStore.savePairing(pairing.copy(deviceSecret = null))
            else ->
                securePairingStore.savePairing(pairing)
        }
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_SYNC_ERROR)
        }
    }

    /**
     * Drops everything scoped to the account we are leaving. None of these tables carries a
     * subscriber column and [com.urlxl.mail.ScopedValue] scopes only the cursors, so without this
     * the previous account's data outlived the pairing that authorised it: cached mail bodies stayed
     * readable (and folders the next account never fetches are never replaced), its contacts merged
     * underneath the next account's, device-contact sync kept publishing them to the OS provider
     * with no pairing at all, and — worst — queued contact changes were flushed to whichever server
     * was paired *next*, uploading one account's contacts to another.
     */
    private suspend fun purgeAccountScopedData() {
        runCatching {
            val db = com.urlxl.mail.data.DataRuntime.graph(context).database
            db.emailDao().clearAll()
            db.contactDao().clearAll()
            db.pendingContactChangeDao().clearAll()
            db.groupDao().clearAll()
            db.groupLinkDao().clearAll()
            db.deviceContactLinkDao().deleteAll()
        }
        // Device-contact sync gates only on its own toggle and Hostile Location Protection, never
        // on having a pairing, so it has to be switched off explicitly here.
        runCatching { com.urlxl.mail.contacts.device.DeviceContactSyncSettings(context).setEnabled(false) }
        runCatching { context.deleteSharedPreferences(com.urlxl.mail.KeywordSettings.PREFS_NAME) }
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

    /**
     * Best-effort server deregistration, then unconditional local clear: even if the network call
     * fails (offline, server already removed the device, credentials already invalid), the device
     * must still be usable to re-pair afterward — local state can never be stuck "paired". Also
     * cancels the periodic pull worker, which [clearPairing] alone does not do.
     */
    suspend fun unpairDevice(deregisterClient: DeregisterClient): DeregisterResult {
        val pairing = pairingForAuthenticatedCall()
        val networkResult = if (pairing != null) {
            deregisterClient.deregister(pairing)
        } else {
            DeregisterResult.Error("Device is not paired")
        }
        clearPairing()
        PullScheduler.cancelPeriodic(context)
        return networkResult
    }

    /** Persist the authoritative delivery mode and (derived or server-provided) pull endpoint. */
    suspend fun updateDelivery(mode: DeliveryMode, pullEndpoint: String?) {
        context.pushDataStore.edit { prefs ->
            prefs[KEY_DELIVERY_MODE] = mode.wire
            if (pullEndpoint.isNullOrBlank()) prefs.remove(KEY_PULL_ENDPOINT) else prefs[KEY_PULL_ENDPOINT] = pullEndpoint
        }
    }

    /** Persist the transport the server confirmed for the last successful registration. */
    suspend fun updateTransport(transport: String?) {
        context.pushDataStore.edit { prefs ->
            if (transport.isNullOrBlank()) prefs.remove(KEY_TRANSPORT) else prefs[KEY_TRANSPORT] = transport
        }
    }

    /**
     * Persist the UnifiedPush endpoint + WebPush encryption keys from the last successful
     * unifiedpush registration, so a later resync can resend the same endpoint/keys instead of
     * falling back to an FCM token — there is no synchronous way to re-fetch these from the
     * UnifiedPush connector, they only ever arrive via the onNewEndpoint callback. Pass all-null
     * to clear (e.g. when the confirmed transport is no longer unifiedpush).
     */
    suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?) {
        context.pushDataStore.edit { prefs ->
            if (endpoint.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT) else prefs[KEY_UNIFIEDPUSH_ENDPOINT] = endpoint
            if (p256dh.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_P256DH) else prefs[KEY_UNIFIEDPUSH_P256DH] = p256dh
            if (auth.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_AUTH) else prefs[KEY_UNIFIEDPUSH_AUTH] = auth
        }
    }

    /**
     * The durable pull cursor for [subscriberId], defaulting to 0. Scoped to the subscriber so
     * re-pairing as a different subscriber starts from a clean cursor rather than skipping their
     * backlog.
     */
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
            transport = prefs[KEY_TRANSPORT],
            unifiedPushEndpoint = prefs[KEY_UNIFIEDPUSH_ENDPOINT],
            unifiedPushP256dh = prefs[KEY_UNIFIEDPUSH_P256DH],
            unifiedPushAuth = prefs[KEY_UNIFIEDPUSH_AUTH],
        )
    }

    private fun decodeHistory(value: String?): List<PushPayload> {
        if (value.isNullOrBlank()) return emptyList()
        return runCatching { json.decodeFromString<List<PushPayload>>(value) }.getOrDefault(emptyList())
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
    val transport: String? = null,
    val unifiedPushEndpoint: String? = null,
    val unifiedPushP256dh: String? = null,
    val unifiedPushAuth: String? = null,
)
