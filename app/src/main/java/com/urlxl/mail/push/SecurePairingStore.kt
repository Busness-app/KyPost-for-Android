package com.urlxl.mail.push

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.urlxl.mail.security.CredentialCipher
import com.urlxl.mail.security.CredentialKeys
import com.urlxl.mail.security.WrappedSecret
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

private const val ENCRYPTED_PREFS_FILE_NAME = "push_pairing_secure"

private const val KEY_SUBSCRIBER_ID = "pair_sub"
private const val KEY_DEVICE_SECRET = "pair_device_secret"
private const val KEY_SERVER_URL = "pair_srv"
private const val KEY_REGISTRATION_URL = "pair_reg"
private const val KEY_PAIRING_TOKEN = "pair_pt"
private const val KEY_DEVICE_ID = "pair_device_id"
private const val KEY_PAIRED_AT = "pair_paired_at"
private const val KEY_DEVICE_SECRET_CIPHERTEXT = "pair_device_secret_ciphertext"
private const val KEY_DEVICE_SECRET_SALT = "pair_device_secret_salt"
private const val KEY_DEVICE_SECRET_IV = "pair_device_secret_iv"
private const val KEY_DEVICE_SECRET_VERSION = "pair_device_secret_version"
private const val KEY_TLS_PIN = "pair_tls_spki_pin"
private const val KEY_TLS_PIN_HOST = "pair_tls_spki_pin_host"

/** A TOFU certificate pin together with the host it was actually observed on. The host used to be
 *  inferred from the pairing's `serverUrl` at enforcement time, while the pin itself came from the
 *  *registration* URL's handshake — two different URLs, one pin, correct only by coincidence. */
data class TlsPin(val host: String, val spkiSha256: String)

/**
 * Holds pairing proof material (device secret, pairing token) in a Keystore-backed
 * EncryptedSharedPreferences file rather than the plaintext DataStore used for the rest of the
 * push state (history, sync status, server URL setting).
 *
 * Construct this exactly once, in [PushGraph]. It owns a [StateFlow] of the current pairing, and
 * the four ad-hoc `SecurePairingStore(context)` call sites that used to exist each had their own
 * copy of that flow — so a write through one instance never reached the collector on another, and
 * `PushRepository` could keep reporting a pairing that had already been cleared.
 */
class SecurePairingStore(context: Context) {
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(context.applicationContext) }

    private val _pairing = MutableStateFlow<PairingData?>(null)
    val pairing: StateFlow<PairingData?> = _pairing.asStateFlow()

    /**
     * The TOFU pin, cached in memory.
     *
     * [currentTlsPin] is called on *every* HTTP request (see
     * [com.urlxl.mail.push.PinnedOrFallbackCallFactory]), and reading it from
     * `EncryptedSharedPreferences` means two AES-SIV key decryptions plus two AES-GCM value
     * decryptions per request — paid on the calling thread, before the socket is touched, on an
     * inbox refresh that runs every 90 seconds.
     *
     * Freshness is preserved exactly: [saveTlsPin] and [clearPairing] are the only writers, and
     * both update this. The comment on [currentTlsPin] used to justify the per-call read as
     * necessary for re-pairing to take effect; keeping the single owner of the file also the owner
     * of the cache gets the same guarantee for a volatile field read.
     */
    @Volatile
    private var cachedTlsPin: TlsPin? = null

    init {
        _pairing.value = readPairing(credentialKeys = null)
        cachedTlsPin = readTlsPin()
    }

    suspend fun savePairing(
        pairing: PairingData,
        credentialKeys: CredentialKeys? = null,
        credentialSalt: ByteArray? = null,
    ) {
        withContext(Dispatchers.IO + NonCancellable) {
            val editor = prefs.edit()
                .putString(KEY_SUBSCRIBER_ID, pairing.subscriberId)
                .putString(KEY_SERVER_URL, pairing.serverUrl)
                .putString(KEY_REGISTRATION_URL, pairing.registrationUrl)
                .putString(KEY_PAIRING_TOKEN, pairing.pairingToken)
                .putLong(KEY_PAIRED_AT, pairing.pairedAtEpochMs)
            if (pairing.deviceId.isNullOrBlank()) editor.remove(KEY_DEVICE_ID) else editor.putString(KEY_DEVICE_ID, pairing.deviceId)

            val deviceSecret = pairing.deviceSecret
            when {
                deviceSecret.isNullOrBlank() -> editor.clearWrappedSecret().remove(KEY_DEVICE_SECRET)
                credentialKeys != null && credentialSalt != null -> {
                    val wrapped = CredentialCipher.wrap(deviceSecret, credentialKeys.current)
                    editor.remove(KEY_DEVICE_SECRET)
                        .putString(KEY_DEVICE_SECRET_CIPHERTEXT, Base64.encodeToString(wrapped.ciphertext, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_SALT, Base64.encodeToString(credentialSalt, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_IV, Base64.encodeToString(wrapped.iv, Base64.NO_WRAP))
                        .putInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_PEPPERED)
                }
                else -> editor.clearWrappedSecret().putString(KEY_DEVICE_SECRET, deviceSecret)
            }
            editor.commit()
        }
        _pairing.value = readPairing(credentialKeys = null)
    }

    /** Reads pairing state, unwrapping `deviceSecret` with [credentialKeys] if it was stored
     *  wrapped. Returns the same shape either way; `deviceSecret` comes back `null` if it's
     *  wrapped and [credentialKeys] is null or wrong — never throws. */
    fun pairingSnapshot(credentialKeys: CredentialKeys?): PairingData? = readPairing(credentialKeys)

    /**
     * True when the stored `deviceSecret` is not wrapped under the current scheme while the
     * credential gate is on — either not wrapped at all (a background FCM token rotation ran in a
     * process that was never PIN-unlocked) or wrapped at [SECRET_VERSION_LEGACY], from before the
     * Keystore pepper existed. Both are closed by [com.urlxl.mail.security.rewrapPairingIfNeeded].
     */
    fun needsCredentialRewrap(): Boolean {
        if (!prefs.contains(KEY_DEVICE_SECRET_CIPHERTEXT)) return true
        return prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY) < SECRET_VERSION_PEPPERED
    }

    /** Persists the TOFU TLS pin captured right after the first successful pairing, together with
     *  the host whose handshake produced it — never overwritten on later requests, only on a fresh
     *  pairing (initial or after [clearPairing] + re-pair). */
    suspend fun saveTlsPin(pin: TlsPin) {
        withContext(Dispatchers.IO + NonCancellable) {
            prefs.edit()
                .putString(KEY_TLS_PIN, pin.spkiSha256)
                .putString(KEY_TLS_PIN_HOST, pin.host)
                .commit()
        }
        cachedTlsPin = pin
    }

    /** The currently enforced TLS pin, or null if this device has never captured one (not yet
     *  paired, or paired before this feature existed — in which case the host is unknown and the
     *  stale pin is ignored rather than applied to a host it may not have come from).
     *
     *  Served from [cachedTlsPin]; this is on the hot path of every request. */
    fun currentTlsPin(): TlsPin? = cachedTlsPin

    private fun readTlsPin(): TlsPin? {
        val pin = prefs.getString(KEY_TLS_PIN, null) ?: return null
        val host = prefs.getString(KEY_TLS_PIN_HOST, null) ?: return null
        return TlsPin(host = host, spkiSha256 = pin)
    }

    suspend fun clearPairing() {
        withContext(Dispatchers.IO + NonCancellable) {
            prefs.edit()
                .remove(KEY_SUBSCRIBER_ID)
                .remove(KEY_DEVICE_SECRET)
                .clearWrappedSecret()
                .remove(KEY_SERVER_URL)
                .remove(KEY_REGISTRATION_URL)
                .remove(KEY_PAIRING_TOKEN)
                .remove(KEY_DEVICE_ID)
                .remove(KEY_PAIRED_AT)
                .remove(KEY_TLS_PIN)
                .remove(KEY_TLS_PIN_HOST)
                .commit()
        }
        _pairing.value = null
        cachedTlsPin = null
    }

    private fun SharedPreferences.Editor.clearWrappedSecret(): SharedPreferences.Editor =
        remove(KEY_DEVICE_SECRET_CIPHERTEXT)
            .remove(KEY_DEVICE_SECRET_SALT)
            .remove(KEY_DEVICE_SECRET_IV)
            .remove(KEY_DEVICE_SECRET_VERSION)

    private fun readPairing(credentialKeys: CredentialKeys?): PairingData? {
        val subId = prefs.getString(KEY_SUBSCRIBER_ID, null).orEmpty()
        val serverUrl = prefs.getString(KEY_SERVER_URL, null).orEmpty()
        val registrationUrl = prefs.getString(KEY_REGISTRATION_URL, null).orEmpty()
        val pairingToken = prefs.getString(KEY_PAIRING_TOKEN, null).orEmpty()
        val pairedAt = if (prefs.contains(KEY_PAIRED_AT)) prefs.getLong(KEY_PAIRED_AT, 0L) else null

        if (subId.isBlank() || serverUrl.isBlank() ||
            registrationUrl.isBlank() || pairingToken.isBlank() || pairedAt == null
        ) {
            return null
        }

        return PairingData(
            subscriberId = subId,
            serverUrl = serverUrl,
            registrationUrl = registrationUrl,
            pairingToken = pairingToken,
            deviceId = prefs.getString(KEY_DEVICE_ID, null),
            deviceSecret = resolveDeviceSecret(credentialKeys),
            pairedAtEpochMs = pairedAt,
        )
    }

    private fun resolveDeviceSecret(credentialKeys: CredentialKeys?): String? {
        val wrappedCiphertext = prefs.getString(KEY_DEVICE_SECRET_CIPHERTEXT, null)
            ?: return prefs.getString(KEY_DEVICE_SECRET, null)
        val keys = credentialKeys ?: return null
        val iv = prefs.getString(KEY_DEVICE_SECRET_IV, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        val ciphertext = Base64.decode(wrappedCiphertext, Base64.NO_WRAP)
        // The salt (KEY_DEVICE_SECRET_SALT) isn't read here — the keys were already derived from
        // it by the caller (see AppLockManager); it's exposed separately for that derivation.
        val key = when (prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY)) {
            SECRET_VERSION_PEPPERED -> keys.current
            else -> keys.legacy
        }
        return CredentialCipher.unwrap(WrappedSecret(iv, ciphertext), key)
    }

    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences {
        return try {
            createEncryptedPrefs(appContext)
        } catch (e: Exception) {
            // The Keystore-backed key can become unable to decrypt the stored keyset (e.g. OS-level
            // key invalidation) — unrecoverable, and it happens in the init path, so an uncaught
            // failure here crashes the app on every launch. Reset to a fresh, empty encrypted file
            // instead; readPairing() then reports null and the user just re-pairs. Failing closed
            // is correct here: losing the pairing revokes this device's access.
            android.util.Log.e("SecurePairingStore", "Encrypted pairing store unreadable, resetting", e)
            appContext.deleteSharedPreferences(ENCRYPTED_PREFS_FILE_NAME)
            createEncryptedPrefs(appContext)
        }
    }

    private fun createEncryptedPrefs(appContext: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            appContext,
            ENCRYPTED_PREFS_FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    companion object {
        /** Bare PBKDF2 wrapping key, written by builds before the Keystore pepper existed. Read-only
         *  — [needsCredentialRewrap] reports these so they get migrated on the next PIN unlock. */
        const val SECRET_VERSION_LEGACY = 1

        /** PBKDF2 output mixed with the non-exportable Keystore pepper; see [CredentialCipher]. */
        const val SECRET_VERSION_PEPPERED = 2
    }
}
