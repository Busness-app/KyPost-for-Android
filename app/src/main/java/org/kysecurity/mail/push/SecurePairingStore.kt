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

/** A TOFU certificate pin together with the host it was actually observed on. The host used to be
 *  inferred from the pairing's `serverUrl` at enforcement time, while the pin itself came from the
 *  *registration* URL's handshake — two different URLs, one pin, correct only by coincidence. */
data class TlsPin(val host: String, val spkiSha256: String)

/**
 * Why a request is or is not pinned.
 *
 * Exists so "we have never paired" cannot be answered the same way as "we had a pin and it is
 * gone". The first is the legitimate TOFU window and must allow an unpinned connection; the second
 * is a downgrade and must fail closed.
 */
sealed interface TlsPinState {
    /** No pairing has ever completed, so there is nothing to pin against yet. */
    object NeverPaired : TlsPinState
    data class Pinned(val pin: TlsPin) : TlsPinState

    /** A pin was captured once and is no longer readable. Requests must fail rather than downgrade. */
    object Lost : TlsPinState
}

/**
 * What [SecurePairingStore.savePairing] should do with the stored `deviceSecret`.
 */
sealed interface SecretWrite {
    /** Leave whatever is on disk untouched — the caller is not allowed to persist one right now. */
    object Preserve : SecretWrite

    /** There is no secret; remove any stored one. */
    object Clear : SecretWrite

    /** Store it wrapped behind the PIN-derived credential key.
     *
     *  **Not a `data class`.** The generated `toString()` prints `secret=` followed by the pairing
     *  device secret in the clear, so one interpolation into a log line or an exception message
     *  puts this device's bearer credential in logcat. The generated `equals`/`hashCode` would also
     *  be identity-over-[ByteArray] on `salt`, which is the trap [org.kysecurity.mail.security.WrappedSecret]
     *  and [org.kysecurity.mail.security.PinHash] already refuse for the same reason. Nothing
     *  compares or prints these. */
    class Wrapped(val secret: String, val keys: CredentialKeys, val salt: ByteArray) : SecretWrite {
        override fun toString(): String = "SecretWrite.Wrapped(secret=<redacted>)"
    }

    /** Store it as-is; the credential gate is off. */
    data class Plaintext(val secret: String) : SecretWrite
}

/**
 * Holds pairing proof material (device secret, pairing token) in a Keystore-backed
 * EncryptedSharedPreferences file rather than the plaintext DataStore used for the rest of the
 * push state (history, sync status, server URL setting).
 */
class SecurePairingStore(context: Context) {
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(context.applicationContext) }

    private val _pairing = MutableStateFlow<PairingData?>(null)
    val pairing: StateFlow<PairingData?> = _pairing.asStateFlow()

    /** The TOFU pin, cached because [currentTlsPin] is on the hot path of every HTTP request and
     *  the backing file costs four AES operations to read. **Invariant:** [saveTlsPin] and
     *  [clearPairing] are the only writers and both must update this. */
    @Volatile
    private var cachedTlsPin: TlsPin? = null

    /** Plain, unencrypted companion to [KEY_TLS_PIN] — see [tlsPinState]. Same shape and same
     *  reason as [org.kysecurity.mail.security.AppLockStore]'s tripwire: a marker that survives the
     *  encrypted file being reset, so "the pin vanished" is distinguishable from "there never was
     *  one". */
    private val tlsPinTripwire =
        context.applicationContext.getSharedPreferences(TLS_PIN_TRIPWIRE_PREFS, Context.MODE_PRIVATE)

    init {
        _pairing.value = readPairing(credentialKeys = null)
        cachedTlsPin = readTlsPin()
    }

    /**
     * Writes the pairing, applying [secret] to the stored `deviceSecret`.
     *
     * The secret's fate is a [SecretWrite], not a nullable `String` plus a `preserveStoredSecret`
     * boolean. Those two encoded four intentions in two arguments, and two of them meant opposite
     * things: `deviceSecret = null` was "delete it" from one caller and "leave it alone" from
     * another, and getting that wrong destroyed a credential the user cannot get back — the server
     * had just minted a replacement and invalidated the previous one, leaving the device with no
     * usable secret, a UI still reading "Paired", and no repair path
     * ([org.kysecurity.mail.security.rewrapPairingIfNeeded] bails on a blank secret, and turning the
     * gate back off unwraps a value that is no longer there). A sealed type makes each intention
     * say its own name and makes the `when` exhaustive.
     */
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

    /** Convenience for the callers that hold a pairing and want its own secret written under the
     *  current gate posture: wrapped when keys are supplied, plaintext when they are not, and
     *  [SecretWrite.Clear] when the pairing carries no secret at all. */
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

    /** Whether a pairing exists on disk at all, without decrypting anything. Distinguishes "there
     *  is no secret to strand" from "there is one and we cannot read it" — see
     *  [org.kysecurity.mail.security.SecuritySettingsActivity]'s unwrap path, where the two used to
     *  be conflated into a silent `return`. */
    fun hasStoredPairing(): Boolean = !prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()

    /** Reads pairing state, unwrapping `deviceSecret` with [credentialKeys] if it was stored
     *  wrapped. Returns the same shape either way; `deviceSecret` comes back `null` if it's
     *  wrapped and [credentialKeys] is null or wrong — never throws. */
    fun pairingSnapshot(credentialKeys: CredentialKeys?): PairingData? = readPairing(credentialKeys)

    /**
     * True when the stored `deviceSecret` is not wrapped under the current scheme while the
     * credential gate is on — either not wrapped at all (a background FCM token rotation ran in a
     * process that was never PIN-unlocked) or wrapped at [SECRET_VERSION_LEGACY], from before the
     * Keystore pepper existed. Both are closed by [org.kysecurity.mail.security.rewrapPairingIfNeeded].
     */
    fun needsCredentialRewrap(): Boolean {
        // No pairing means no secret to wrap. Without this, an unpaired device answered "yes"
        // forever, so every PIN unlock ran the full rewrap dance — Keystore read, pairing snapshot,
        // AES — before bailing out at the first null. Cheapest possible check, and it is the same
        // field readPairing() treats as the pairing's existence.
        if (prefs.getString(KEY_SUBSCRIBER_ID, null).isNullOrBlank()) return false
        if (!prefs.contains(KEY_DEVICE_SECRET_CIPHERTEXT)) return true
        return prefs.getInt(KEY_DEVICE_SECRET_VERSION, SECRET_VERSION_LEGACY) < SECRET_VERSION_PEPPERED
    }

    /** Persists the TOFU TLS pin captured right after the first successful pairing, together with
     *  the host whose handshake produced it — never overwritten on later requests, only on a fresh
     *  pairing (initial or after [clearPairing] + re-pair). */
    suspend fun saveTlsPin(pin: TlsPin) {
        // ORDER: marker, then pin, then cache. All three orderings fail at *something*; only
        // this one fails closed.
        //
        // Publishing the cache first — which is what this did, to close a window where
        // `currentTlsPin()` was null while the marker already read as captured — opens the mirror
        // window: the cache says Pinned while nothing is on disk. A process death in it (an OOM
        // kill, a force-stop, an OEM battery killer, all most likely on the memory-heavy pairing
        // screen) leaves no pin AND no marker, so the next launch reads `NeverPaired` and serves
        // every credential-bearing request over bare system-CA trust, permanently and silently.
        // That is the downgrade `TlsPinState.Lost` exists to refuse.
        //
        // With the marker first, the same interruption yields `Lost`: requests refuse, the user
        // re-pairs, and the failure is visible and recoverable.
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

    /** The currently enforced TLS pin, or null if this device has never captured one — including
     *  a pin stored without its host, which is ignored rather than applied to a host it may not
     *  have come from. */
    fun currentTlsPin(): TlsPin? = cachedTlsPin

    /**
     * The pin, or why there isn't one. **"No pin yet" and "the pin is gone" are different answers
     * and must not be collapsed.**
     */
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

    /** See [openEncryptedPrefs]. A reset costs the pairing AND the TOFU TLS pin, so it happens only
     *  for an undecryptable keyset — never for a transient I/O failure, which is what the bare
     *  `catch (Exception)` this replaces treated identically. */
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
