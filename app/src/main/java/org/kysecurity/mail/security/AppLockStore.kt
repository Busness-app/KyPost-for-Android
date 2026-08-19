// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.security.MessageDigest

private const val ENCRYPTED_PREFS_FILE_NAME = "app_lock_secure"

/** Unencrypted companion file to [ENCRYPTED_PREFS_FILE_NAME]; see [AppLockStore.tripwire]. */
private const val TRIPWIRE_PREFS_FILE_NAME = "app_lock_tripwire"
private const val KEY_TRIPWIRE_LOCK_WAS_ENABLED = "lock_was_enabled"

/** HMAC over [KEY_TRIPWIRE_LOCK_WAS_ENABLED] under [KeystoreTripwireKey]; see [AppLockStore.tripwire]. */
private const val KEY_TRIPWIRE_MAC = "lock_was_enabled_mac"

private const val TAG = "AppLockStore"

private const val KEY_LOCK_ENABLED = "lock_enabled"
private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
private const val KEY_CREDENTIAL_PIN_GATE_ENABLED = "credential_pin_gate_enabled"
private const val KEY_PIN_SALT = "pin_salt"
private const val KEY_PIN_HASH = "pin_hash"

/** Absent means v1 (bare PBKDF2) — see [PinHasher.VERSION_LEGACY_UNPEPPERED]. */
private const val KEY_PIN_HASH_VERSION = "pin_hash_version"
private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
private const val KEY_LOCKOUT_UNTIL_ELAPSED = "lockout_until_elapsed_ms"
private const val KEY_LOCKOUT_DURATION = "lockout_duration_ms"
private const val KEY_CREDENTIAL_SALT = "credential_salt"

/** Absent means never chosen (the default); [WIPE_DISABLED] stores "the user turned it off". */
private const val KEY_WIPE_AFTER_ATTEMPTS = "wipe_after_attempts"
private const val WIPE_DISABLED = -1

/** UNREADABLE is deliberate: neither answer is safe, so [LockedActivity] blocks instead. */
enum class TripwireState {
    NEVER_CONFIGURED,
    CONFIGURED,

    /** The Keystore could not be consulted, so neither answer above is knowable. */
    UNREADABLE,
}

/** Everything [AppLockManager] needs from persisted app-lock state, kept as an interface so
 *  [AppLockManager] can be unit-tested against a fake instead of a real Context/Keystore. */
interface AppLockState {
    fun isLockEnabled(): Boolean

    /** No `setLockEnabled(false)`: disarming is [reset], which also destroys the key and hash. */
    fun enableLock()
    fun isBiometricEnabled(): Boolean
    fun setBiometricEnabled(enabled: Boolean)
    fun isCredentialPinGateEnabled(): Boolean
    fun setCredentialPinGateEnabled(enabled: Boolean)
    fun setPin(pin: CharArray)
    fun verifyPin(pin: CharArray): Boolean
    fun hasPin(): Boolean
    fun incrementFailedAttempts(): Int
    fun resetFailedAttempts()

    /** Monotonic elapsedRealtime, not wall clock; [lockoutDurationMs] clamps it after a reboot. */
    fun lockoutUntilElapsedMs(): Long
    fun lockoutDurationMs(): Long
    fun setLockout(untilElapsedMs: Long, durationMs: Long)

    /** Null when the wipe is off. Encrypted, because it decides whether mail is destroyed. */
    fun wipeAfterAttempts(): Int?
    fun setWipeAfterAttempts(attempts: Int?)

    /** Persisted once: regenerating it makes already-wrapped secrets undecryptable. */
    fun credentialSalt(): ByteArray?

    /** Returns the persisted salt, minting [candidate] only if there is none.
     *
     *  Compare-and-set, not check-and-throw: two stores racing the first mint must both come back
     *  with the winner's salt. Throwing here escaped [AppLockManager]'s PIN paths, which catch only
     *  [PepperUnavailableException], and crashed the coroutine mid-authentication. */
    fun putCredentialSaltIfAbsent(candidate: ByteArray): ByteArray

    /** Clears PIN, lock/biometric/credential-gate flags, and attempt counters — the app-lock
     *  half of [SecurityWipe]'s full wipe, also used by "turn off Require Unlock to Open". */
    fun reset()
}

/** Every write uses commit(): apply() lets a force-stop drop the failed-attempt counter. */
class AppLockStore(context: Context) : AppLockState {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(appContext) }

    /** Marker for "a lock was configured": this file plus the unforgeable [KeystoreTripwireKey]. */
    private val tripwire: SharedPreferences =
        appContext.getSharedPreferences(TRIPWIRE_PREFS_FILE_NAME, Context.MODE_PRIVATE)

    /** Fails towards CONFIGURED on tampering, and towards UNREADABLE when the Keystore is mute. */
    fun tripwireState(): TripwireState {
        val claimed = tripwire.getBoolean(KEY_TRIPWIRE_LOCK_WAS_ENABLED, false)
        val storedMac = tripwire.getString(KEY_TRIPWIRE_MAC, null)

        val keyPresent = try {
            KeystoreTripwireKey.exists()
        } catch (e: PepperUnavailableException) {
            Log.e(TAG, "Could not consult the tripwire key", e)
            return TripwireState.UNREADABLE
        }
        if (!keyPresent) return TripwireState.NEVER_CONFIGURED

        if (storedMac == null) {
            Log.e(TAG, "Tripwire key exists but its marker is gone; treating as tampering")
            return TripwireState.CONFIGURED
        }
        val expected = runCatching { KeystoreTripwireKey.mix(tripwirePayload(claimed)) }.getOrNull()
        if (expected == null) {
            Log.e(TAG, "Tripwire marker could not be recomputed; treating as tampering")
            return TripwireState.CONFIGURED
        }
        val actual = runCatching { Base64.decode(storedMac, Base64.NO_WRAP) }.getOrNull()
        if (actual == null || !MessageDigest.isEqual(expected, actual)) {
            Log.e(TAG, "Tripwire marker failed authentication; treating as tampering")
            return TripwireState.CONFIGURED
        }
        return if (claimed) TripwireState.CONFIGURED else TripwireState.NEVER_CONFIGURED
    }

    /** UNREADABLE answers false here; [LockedActivity] handles it by refusing to open at all. */
    fun wasLockEnabled(): Boolean = tripwireState() == TripwireState.CONFIGURED

    /** One byte, so the MAC covers the value and not just the fact that a marker exists. */
    private fun tripwirePayload(enabled: Boolean): ByteArray = byteArrayOf(if (enabled) 1 else 0)

    private fun writeTripwire(enabled: Boolean) {
        val mac = KeystoreTripwireKey.mix(tripwirePayload(enabled))
        tripwire.edit()
            .putBoolean(KEY_TRIPWIRE_LOCK_WAS_ENABLED, enabled)
            .putString(KEY_TRIPWIRE_MAC, Base64.encodeToString(mac, Base64.NO_WRAP))
            .commit()
    }

    /** True when the encrypted store lost its contents while [wasLockEnabled] says a lock was
     *  configured. [SecurityWipe.enforceTripwire] turns this into a wipe at startup.
     *
     *  NULL means the encrypted store could not be opened at all, which is neither answer. That
     *  case must never be rounded down to "the PIN hash is gone": it is a transient Keystore fault
     *  far more often than it is tampering, and this return value destroys the mailbox. Callers
     *  block instead — see [LockedActivity.passesStartupTripwire]. */
    fun tripwireBroken(): Boolean? {
        if (!wasLockEnabled()) return false
        val store = try {
            prefs
        } catch (e: EncryptedStoreUnavailableException) {
            Log.e(TAG, "The app-lock store could not be opened; refusing to call the tripwire", e)
            return null
        }
        return !store.contains(KEY_PIN_HASH)
    }

    /** Whether the encrypted half can be read right now. Disk and Keystore work: call it off the
     *  main thread, and prefer [SecurityWipe.lockStoreUnreadable], which caches one answer. */
    fun encryptedStoreReadable(): Boolean = runCatching { prefs }.isSuccess

    override fun isLockEnabled(): Boolean = prefs.getBoolean(KEY_LOCK_ENABLED, false)
    override fun enableLock() {
        // Tripwire key FIRST: writing the marker before the key it is authenticated with exists
        // would leave an unverifiable marker, which tripwireState() reads as tampering.
        KeystoreTripwireKey.ensureExists()
        prefs.edit().putBoolean(KEY_LOCK_ENABLED, true).commit()
        writeTripwire(true)
    }

    override fun isBiometricEnabled(): Boolean = prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    override fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).commit()
    }

    override fun isCredentialPinGateEnabled(): Boolean = prefs.getBoolean(KEY_CREDENTIAL_PIN_GATE_ENABLED, false)
    override fun setCredentialPinGateEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CREDENTIAL_PIN_GATE_ENABLED, enabled).commit()
    }

    override fun setPin(pin: CharArray) {
        val hash = PinHasher.hash(pin)
        prefs.edit()
            .putString(KEY_PIN_SALT, Base64.encodeToString(hash.salt, Base64.NO_WRAP))
            .putString(KEY_PIN_HASH, Base64.encodeToString(hash.hash, Base64.NO_WRAP))
            .putInt(KEY_PIN_HASH_VERSION, PinHasher.VERSION_PEPPERED)
            .commit()
    }

    override fun hasPin(): Boolean = prefs.contains(KEY_PIN_HASH)

    override fun verifyPin(pin: CharArray): Boolean {
        val salt = prefs.getString(KEY_PIN_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val hash = prefs.getString(KEY_PIN_HASH, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val version = prefs.getInt(KEY_PIN_HASH_VERSION, PinHasher.VERSION_LEGACY_UNPEPPERED)

        if (version >= PinHasher.VERSION_PEPPERED) return PinHasher.matches(pin, salt, hash)

        // Pre-pepper hash: upgrade in place, but only on a correct PIN.
        if (!PinHasher.matchesLegacy(pin, salt, hash)) return false
        setPin(pin)
        return true
    }

    override fun incrementFailedAttempts(): Int = synchronized(counterLock) {
        val next = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        prefs.edit().putInt(KEY_FAILED_ATTEMPTS, next).commit()
        next
    }

    override fun resetFailedAttempts() {
        synchronized(counterLock) {
            prefs.edit()
                .putInt(KEY_FAILED_ATTEMPTS, 0)
                .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
                .putLong(KEY_LOCKOUT_DURATION, 0L)
                .commit()
        }
    }

    override fun lockoutUntilElapsedMs(): Long = prefs.getLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
    override fun lockoutDurationMs(): Long = prefs.getLong(KEY_LOCKOUT_DURATION, 0L)
    override fun setLockout(untilElapsedMs: Long, durationMs: Long) {
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, untilElapsedMs)
            .putLong(KEY_LOCKOUT_DURATION, durationMs)
            .commit()
    }

    override fun wipeAfterAttempts(): Int? {
        val stored = prefs.getInt(KEY_WIPE_AFTER_ATTEMPTS, LockoutPolicy.DEFAULT_WIPE_THRESHOLD)
        return if (stored == WIPE_DISABLED) null else stored
    }

    override fun setWipeAfterAttempts(attempts: Int?) {
        prefs.edit().putInt(KEY_WIPE_AFTER_ATTEMPTS, attempts ?: WIPE_DISABLED).commit()
    }

    override fun credentialSalt(): ByteArray? =
        prefs.getString(KEY_CREDENTIAL_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) }

    /** Never overwrites: a second salt makes every already-wrapped secret undecryptable. Under
     *  [counterLock], which is shared across instances — a field lock would not order two stores. */
    override fun putCredentialSaltIfAbsent(candidate: ByteArray): ByteArray = synchronized(counterLock) {
        credentialSalt() ?: candidate.also {
            prefs.edit().putString(KEY_CREDENTIAL_SALT, Base64.encodeToString(it, Base64.NO_WRAP)).commit()
        }
    }

    override fun reset() {
        // Tripwire FIRST: clearing the store first leaves a window that reads as a broken tripwire.
        tripwire.edit().clear().commit()
        // Left behind, the durable half would arm a wipe on the next launch.
        KeystoreTripwireKey.destroy()
        prefs.edit().clear().commit()
    }

    /** [reset] plus the step names it could not clear, so [SecurityWipe] can report an incomplete
     *  wipe rather than a clean one when a Keystore alias outlives it. */
    fun resetReportingLeftovers(): List<String> {
        reset()
        val leftBehind = runCatching { KeystoreTripwireKey.exists() }.getOrDefault(true)
        return if (leftBehind) listOf("deleteTripwireKey") else emptyList()
    }

    /** A reset here does NOT mean no lock was set; the tripwire above still says one was. */
    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =
        openEncryptedPrefs(appContext, ENCRYPTED_PREFS_FILE_NAME) {
            android.util.Log.e(TAG, "Encrypted app-lock store keyset is undecryptable", it)
        }

    private companion object {
        /** Shared across instances: [SecurityWipe] builds its own store; a field lock is none. */
        val counterLock = Any()
    }
}
