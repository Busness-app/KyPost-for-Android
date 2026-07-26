package com.urlxl.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

private const val ENCRYPTED_PREFS_FILE_NAME = "app_lock_secure"

/** Unencrypted companion file to [ENCRYPTED_PREFS_FILE_NAME]; see [AppLockStore.tripwire]. */
private const val TRIPWIRE_PREFS_FILE_NAME = "app_lock_tripwire"
private const val KEY_TRIPWIRE_LOCK_WAS_ENABLED = "lock_was_enabled"

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

/** Everything [AppLockManager] needs from persisted app-lock state, kept as an interface so
 *  [AppLockManager] can be unit-tested against a fake instead of a real Context/Keystore. */
interface AppLockState {
    fun isLockEnabled(): Boolean
    fun setLockEnabled(enabled: Boolean)
    fun isBiometricEnabled(): Boolean
    fun setBiometricEnabled(enabled: Boolean)
    fun isCredentialPinGateEnabled(): Boolean
    fun setCredentialPinGateEnabled(enabled: Boolean)
    fun setPin(pin: String)
    fun verifyPin(pin: String): Boolean
    fun hasPin(): Boolean
    fun incrementFailedAttempts(): Int
    fun resetFailedAttempts()

    /**
     * Lockout deadline on [android.os.SystemClock.elapsedRealtime]'s monotonic timebase, not the
     * wall clock: a wall-clock deadline is cleared by setting the device date forward, which is
     * not a defence at all. [lockoutDurationMs] is stored alongside it purely to clamp the
     * remaining time after a reboot, since elapsedRealtime restarts at zero there and the stored
     * deadline would otherwise read as the device's entire previous uptime.
     */
    fun lockoutUntilElapsedMs(): Long
    fun lockoutDurationMs(): Long
    fun setLockout(untilElapsedMs: Long, durationMs: Long)

    /** PBKDF2 salt for [CredentialCipher.deriveKeys], generated once on first use and persisted —
     *  regenerating it per-unlock would make any secret already wrapped under the old key
     *  undecryptable. Null until [setCredentialSalt] has been called at least once. */
    fun credentialSalt(): ByteArray?
    fun setCredentialSalt(salt: ByteArray)

    /** Clears PIN, lock/biometric/credential-gate flags, and attempt counters — the app-lock
     *  half of [SecurityWipe]'s full wipe, also used by "turn off Require Unlock to Open". */
    fun reset()
}

/**
 * Keystore-backed storage for the app-lock PIN and its associated state — same
 * `EncryptedSharedPreferences` pattern as [com.urlxl.mail.push.SecurePairingStore]. The PIN
 * itself is never stored, only [PinHasher]'s salted hash.
 *
 * Every write here uses `commit()` rather than `apply()` on purpose. `apply()` returns before the
 * write reaches disk, which for [incrementFailedAttempts] specifically would hand an attacker an
 * unlimited-guess bypass: try a PIN, force-stop the app before the async flush lands, repeat with
 * the counter never advancing. These writes are rare and must be durable, so the cost is paid —
 * what changed instead is that [AppLockManager] now keeps every caller off the main thread.
 */
class AppLockStore(context: Context) : AppLockState {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(appContext) }

    /**
     * A plain, unencrypted "the user had a lock configured" marker.
     *
     * The encrypted file above can become unreadable — OS-level Keystore invalidation, or an
     * attacker with filesystem access deleting the keyset. The old behaviour was to recreate it
     * empty, which reported `isLockEnabled() == false` and opened straight into the inbox with
     * every cached message still on disk: deleting one file disabled the lock. This marker
     * survives that, so [tripwireBroken] can tell "never configured" apart from "configured, and
     * the state just vanished" — and the latter is treated as hostile.
     */
    private val tripwire: SharedPreferences =
        appContext.getSharedPreferences(TRIPWIRE_PREFS_FILE_NAME, Context.MODE_PRIVATE)

    fun wasLockEnabled(): Boolean = tripwire.getBoolean(KEY_TRIPWIRE_LOCK_WAS_ENABLED, false)

    /** True when the encrypted store lost its contents while [wasLockEnabled] says a lock was
     *  configured. [SecurityWipe.enforceTripwire] turns this into a wipe at startup. */
    fun tripwireBroken(): Boolean = wasLockEnabled() && !prefs.contains(KEY_PIN_HASH)

    override fun isLockEnabled(): Boolean = prefs.getBoolean(KEY_LOCK_ENABLED, false)
    override fun setLockEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_LOCK_ENABLED, enabled).commit()
        tripwire.edit().putBoolean(KEY_TRIPWIRE_LOCK_WAS_ENABLED, enabled).commit()
    }

    override fun isBiometricEnabled(): Boolean = prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    override fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).commit()
    }

    override fun isCredentialPinGateEnabled(): Boolean = prefs.getBoolean(KEY_CREDENTIAL_PIN_GATE_ENABLED, false)
    override fun setCredentialPinGateEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CREDENTIAL_PIN_GATE_ENABLED, enabled).commit()
    }

    override fun setPin(pin: String) {
        val hash = PinHasher.hash(pin)
        prefs.edit()
            .putString(KEY_PIN_SALT, Base64.encodeToString(hash.salt, Base64.NO_WRAP))
            .putString(KEY_PIN_HASH, Base64.encodeToString(hash.hash, Base64.NO_WRAP))
            .putInt(KEY_PIN_HASH_VERSION, PinHasher.VERSION_PEPPERED)
            .commit()
    }

    override fun hasPin(): Boolean = prefs.contains(KEY_PIN_HASH)

    override fun verifyPin(pin: String): Boolean {
        val salt = prefs.getString(KEY_PIN_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val hash = prefs.getString(KEY_PIN_HASH, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val version = prefs.getInt(KEY_PIN_HASH_VERSION, PinHasher.VERSION_LEGACY_UNPEPPERED)

        if (version >= PinHasher.VERSION_PEPPERED) return PinHasher.matches(pin, salt, hash)

        // Pre-pepper hash from an older install: verify against the v1 derivation, then upgrade in
        // place so the unpeppered value — which is offline-crackable in seconds for a 6-digit PIN —
        // stops existing on disk. Only ever upgrades on a *correct* PIN, so a wrong guess cannot
        // rewrite the verifier.
        if (!PinHasher.matchesLegacy(pin, salt, hash)) return false
        setPin(pin)
        return true
    }

    override fun incrementFailedAttempts(): Int {
        val next = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1
        prefs.edit().putInt(KEY_FAILED_ATTEMPTS, next).commit()
        return next
    }

    override fun resetFailedAttempts() {
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
            .putLong(KEY_LOCKOUT_DURATION, 0L)
            .commit()
    }

    override fun lockoutUntilElapsedMs(): Long = prefs.getLong(KEY_LOCKOUT_UNTIL_ELAPSED, 0L)
    override fun lockoutDurationMs(): Long = prefs.getLong(KEY_LOCKOUT_DURATION, 0L)
    override fun setLockout(untilElapsedMs: Long, durationMs: Long) {
        prefs.edit()
            .putLong(KEY_LOCKOUT_UNTIL_ELAPSED, untilElapsedMs)
            .putLong(KEY_LOCKOUT_DURATION, durationMs)
            .commit()
    }

    override fun credentialSalt(): ByteArray? =
        prefs.getString(KEY_CREDENTIAL_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) }

    override fun setCredentialSalt(salt: ByteArray) {
        prefs.edit().putString(KEY_CREDENTIAL_SALT, Base64.encodeToString(salt, Base64.NO_WRAP)).commit()
    }

    override fun reset() {
        // Tripwire FIRST. `tripwireBroken()` is "a lock was configured but the PIN hash is gone",
        // so clearing the encrypted store first opens a window where that is momentarily true —
        // and process death inside it makes SecurityWipe.enforceTripwire destroy the database, the
        // OS contact rows and the pairing on the next launch, in response to a user turning OFF
        // a setting. This order fails safe instead: an interruption leaves the lock enabled with a
        // valid hash, which the user can simply retry.
        tripwire.edit().clear().commit()
        prefs.edit().clear().commit()
    }

    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences {
        return try {
            createEncryptedPrefs(appContext)
        } catch (e: Exception) {
            // The Keystore-backed key can become unable to decrypt the stored keyset (e.g. OS-level
            // key invalidation), and this runs in the init path — an uncaught failure here crashes
            // the app on every launch. Recreate the file empty so the app is usable, but do NOT
            // treat that as "no lock was ever set": the tripwire above still says one was, and
            // SecurityWipe.enforceTripwire destroys the cached data before it can be read.
            android.util.Log.e("AppLockStore", "Encrypted app-lock store unreadable, resetting", e)
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
}
