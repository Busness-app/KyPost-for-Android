// See AppLockStore: androidx.security-crypto is deprecated in full with no replacement API.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.push

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.kysecurity.mail.security.CredentialCipher
import org.kysecurity.mail.security.openEncryptedPrefs
import org.kysecurity.mail.security.CredentialKeys
import org.kysecurity.mail.security.WrappedSecret
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

/** Plain companion file; see [SecurePairingStore.tlsPinState]. */
internal const val TLS_PIN_TRIPWIRE_PREFS = "push_tls_pin_tripwire"
private const val KEY_TLS_PIN_EVER_CAPTURED = "tls_pin_ever_captured"

/** A TOFU certificate pin together with the host it was actually observed on. */
data class TlsPin(val host: String, val spkiSha256: String)

/** Why a request is or is not pinned: "never paired" must not be answered like "pin is gone". */
sealed interface TlsPinState {
    /** No pairing has ever completed, so there is nothing to pin against yet. */
    object NeverPaired : TlsPinState
    data class Pinned(val pin: TlsPin) : TlsPinState

    /** A pin was captured once and is no longer readable. Requests must fail rather than downgrade. */
    object Lost : TlsPinState
}

/** What [SecurePairingStore.savePairing] should do with the stored `deviceSecret`. */
sealed interface SecretWrite {
    /** Leave whatever is on disk untouched — the caller is not allowed to persist one right now. */
    object Preserve : SecretWrite

    /** There is no secret; remove any stored one. */
    object Clear : SecretWrite

    /** Wrapped behind the PIN-derived key. Not a `data class`: `toString()` would leak the secret. */
    class Wrapped(val secret: String, val keys: CredentialKeys, val salt: ByteArray) : SecretWrite {
        override fun toString(): String = "SecretWrite.Wrapped(secret=<redacted>)"
    }

    /** Store it as-is; the credential gate is off. */
    data class Plaintext(val secret: String) : SecretWrite {
        /** Redacted: the secret is an unwrapped device credential. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Plaintext(redacted)"
    }
}

/** Holds pairing proof material in a Keystore-backed EncryptedSharedPreferences file. */
class SecurePairingStore(context: Context) {
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(context.applicationContext) }

    private val _pairing = MutableStateFlow<PairingData?>(null)
    val pairing: StateFlow<PairingData?> = _pairing.asStateFlow()

    /** Cached for the request hot path. Only [saveTlsPin] and [clearPairing] may write it. */
    @Volatile
    private var cachedTlsPin: TlsPin? = null

    /** Plain marker that survives the encrypted file being reset — see [tlsPinState]. */
    private val tlsPinTripwire =
        context.applicationContext.getSharedPreferences(TLS_PIN_TRIPWIRE_PREFS, Context.MODE_PRIVATE)

    init {
        _pairing.value = readPairing(credentialKeys = null)
        cachedTlsPin = readTlsPin()
    }

    /** Writes the pairing, applying [secret] to the stored `deviceSecret`. */
    suspend fun savePairing(pairing: PairingData, secret: SecretWrite) {
        withContext(Dispatchers.IO + NonCancellable) {
            val editor = prefs.edit()
                .putString(KEY_SUBSCRIBER_ID, pairing.subscriberId)
                .putString(KEY_SERVER_URL, pairing.serverUrl)
                .putString(KEY_REGISTRATION_URL, pairing.registrationUrl)
                .putString(KEY_PAIRING_TOKEN, pairing.pairingToken)
                .putLong(KEY_PAIRED_AT, pairing.pairedAtEpochMs)
            if (pairing.deviceId.isNullOrBlank()) editor.remove(KEY_DEVICE_ID) else editor.putString(KEY_DEVICE_ID, pairing.deviceId)

            when (secret) {
                SecretWrite.Preserve -> Unit
                SecretWrite.Clear -> editor.clearWrappedSecret().remove(KEY_DEVICE_SECRET)
                is SecretWrite.Wrapped -> {
                    val wrapped = CredentialCipher.wrap(secret.secret, secret.keys.current)
                    editor.remove(KEY_DEVICE_SECRET)
                        .putString(KEY_DEVICE_SECRET_CIPHERTEXT, Base64.encodeToString(wrapped.ciphertext, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_SALT, Base64.encodeToString(secret.salt, Base64.NO_WRAP))
                        .putString(KEY_DEVICE_SECRET_IV, Base64.encodeToString(wrapped.iv, Base64.NO_WRAP))
                        .putInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_PEPPERED)
                }
                is SecretWrite.Plaintext ->
                    editor.clearWrappedSecret().putString(KEY_DEVICE_SECRET, secret.secret)
            }
            editor.commit()
        }
        _pairing.value = readPairing(credentialKeys = null)
    }

    /** Writes the pairing's own secret under the current gate posture. */
    suspend fun savePairing(
        pairing: PairingData,
        credentialKeys: CredentialKeys? = null,
        credentialSalt: ByteArray? = null,
    ) {
        val deviceSecret = pairing.deviceSecret
        val secret = when {
            deviceSecret.isNullOrBlank() -> SecretWrite.Clear
            credentialKeys != null && credentialSalt != null ->
                SecretWrite.Wrapped(deviceSecret, credentialKeys, credentialSalt)
            else -> SecretWrite.Plaintext(deviceSecret)
        }
        savePairing(pairing, secret)
    }

    /** Whether a pairing exists on disk at all, without decrypting anything. */
    fun hasStoredPairing(): Boolean = !prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()

    /** Unwraps `deviceSecret`; null if wrapped and [credentialKeys] is wrong. Never throws. */
    fun pairingSnapshot(credentialKeys: CredentialKeys?): PairingData? = readPairing(credentialKeys)

    /** True when the stored secret is not wrapped under the current scheme while the gate is on. */
    fun needsCredentialRewrap(): Boolean {
        // No pairing means no secret to wrap; cheapest possible check before the rewrap dance.
        if (prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()) return false
        if (!prefs.contains(KEY_DEVICE_SECRET_CIPHERTEXT)) return true
        return prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY) < SECRET_VERSION_PEPPERED
    }

    /** Persists the TOFU pin with its host; never overwritten except on a fresh pairing. */
    suspend fun saveTlsPin(pin: TlsPin) {
        // ORDER: marker, then pin, then cache — the only ordering that fails closed.
        withContext(Dispatchers.IO + NonCancellable) {
            // The plain marker, so losing the encrypted file cannot look like "never pinned".
            tlsPinTripwire.edit().putBoolean(KEY_TLS_PIN_EVER_CAPTURED, true).commit()
            prefs.edit()
                .putString(KEY_TLS_PIN, pin.spkiSha256)
                .putString(KEY_TLS_PIN_HOST, pin.host)
                .commit()
        }
        // Last, and before the suspend returns: a cached pin must never outlive its own durability.
        cachedTlsPin = pin
    }

    /** The currently enforced TLS pin, or null if none was ever captured. */
    fun currentTlsPin(): TlsPin? = cachedTlsPin

    /** The pin, or why there isn't one. "No pin yet" and "the pin is gone" must not be collapsed. */
    fun tlsPinState(): TlsPinState {
        cachedTlsPin?.let { return TlsPinState.Pinned(it) }
        return if (tlsPinTripwire.getBoolean(KEY_TLS_PIN_EVER_CAPTURED, false)) {
            TlsPinState.Lost
        } else {
            TlsPinState.NeverPaired
        }
    }

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
            // Deliberate unpair: there genuinely is no pin any more, so the marker goes too and the
            // next pairing gets a clean TOFU window rather than being refused as "lost".
            tlsPinTripwire.edit().clear().commit()
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

    /** See [openEncryptedPrefs]. A reset costs the pairing and the TOFU pin — keyset failures only. */
    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =
        openEncryptedPrefs(appContext, ENCRYPTED_PREFS_FILE_NAME) {
            android.util.Log.e("SecurePairingStore", "Encrypted pairing store keyset is undecryptable", it)
        }

    companion object {
        /** Bare PBKDF2 wrapping key, written by builds before the Keystore pepper existed. Read-only
         *  — [needsCredentialRewrap] reports these so they get migrated on the next PIN unlock. */
        const val SECRET_VERSION_LEGACY = 1

        /** PBKDF2 output mixed with the non-exportable Keystore pepper; see [CredentialCipher]. */
        const val SECRET_VERSION_PEPPERED = 2
    }
}
