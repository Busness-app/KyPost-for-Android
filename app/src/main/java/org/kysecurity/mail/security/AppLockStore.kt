// androidx.security-crypto is deprecated in full with no replacement API. Swapping it out is a
// migration of the at-rest credential format, not a warning fix, so it is deliberately not done
// here. File-scoped because the deprecation also fires on the imports below.
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

/** Absent means "never chosen", which reads as [LockoutPolicy.DEFAULT_WIPE_THRESHOLD]. The
 *  sentinel below is how "the user turned the wipe off" is stored, since absent already means
 *  something else. */
private const val KEY_WIPE_AFTER_ATTEMPTS = "wipe_after_attempts"
private const val WIPE_DISABLED = -1

/**
 * What the app-lock tripwire can actually say, which is three things rather than two.
 *
 * [UNREADABLE] is the one that used to be missing. The Keystore alias is the durable half of the
 * marker, so a Keystore that cannot be consulted leaves the question genuinely unanswered — and
 * both available answers were wrong. Answering "configured" wipes a fresh install over a
 * transient `keystore2` restart; answering with the *file's* claim, which is what this did, hands
 * the decision to an unauthenticated `MODE_PRIVATE` file that anything able to write the sandbox
 * can forge — the exact "write `lock_was_enabled=true` and the next launch destroys the user's
 * mail" attack the Keystore half was introduced to close.
 *
 * So it is not answered here at all. [org.kysecurity.mail.security.LockedActivity] blocks the app
 * until the Keystore can be consulted again, which is neither a wipe nor an unlock.
 */
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

    /** Arms the lock. There is deliberately no `setLockEnabled(false)`: disarming is [reset],
     *  which also destroys the PIN hash and [KeystoreTripwireKey]. A `Boolean` here selected
     *  between two entirely different sequences, and the `false` one — write an authenticated
     *  marker, *then* destroy the key that authenticates it — threw
     *  [PepperUnavailableException] on any device that had never armed the lock. It had no
     *  production caller, so nothing ever ran it. */
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

    /**
     * How many consecutive wrong PINs trigger [SecurityWipe], or null when the user has turned the
     * wipe off.
     *
     * Lives in the encrypted store rather than [AppLockSettings] deliberately: it is the one
     * setting whose value decides whether the user's mail gets destroyed, so it must not be
     * writable by anything that can write a plain preferences file.
     */
    fun wipeAfterAttempts(): Int?
    fun setWipeAfterAttempts(attempts: Int?)

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
 * `EncryptedSharedPreferences` pattern as [org.kysecurity.mail.push.SecurePairingStore]. The PIN
 * itself is never stored, only [PinHasher]'s salted hash.
 *
 * Every write here uses `commit()`, never `apply()`. `apply()` returns before the write reaches
 * disk, which for [incrementFailedAttempts] is an unlimited-guess bypass: try a PIN, force-stop the
 * app before the async flush lands, repeat with the counter never advancing. [AppLockManager] keeps
 * every caller off the main thread so the durability can be afforded.
 */
class AppLockStore(context: Context) : AppLockState {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildEncryptedPrefs(appContext) }

    /**
     * The "a lock was configured" marker: a preference file **plus** [KeystoreTripwireKey].
     *
     * The encrypted store above can become unreadable — Keystore invalidation, or an attacker
     * deleting the keyset — and recreating it empty would report `isLockEnabled() == false`, so
     * deleting one file would disable the lock. This marker lets [tripwireBroken] tell "never
     * configured" apart from "configured, and the state just vanished", and treat the latter as
     * hostile.
     *
     * **The Keystore half is what makes it a control rather than a speed bump.** As a bare
     * `MODE_PRIVATE` file this was both defeatable and weaponisable by anyone who could write the
     * app sandbox: delete both preference files and the lock is gone with no wipe, or write
     * `lock_was_enabled=true` onto a device that never had a lock and the next launch destroys the
     * user's mail. The alias cannot be forged or deleted by writing files, so its presence is the
     * durable claim and the HMAC below is what binds the file's value to it.
     *
     * **Scope boundary.** The tripwire only fires at app *launch*, so it defends the UI against
     * someone who tampers and then uses the app. The at-rest protection for the cached mail itself
     * is SQLCipher (see [DatabaseKey]), with Hostile Location Protection
     * ([HostileLocationSettings]) as the stronger mode in which no file exists at all.
     */
    private val tripwire: SharedPreferences =
        appContext.getSharedPreferences(TRIPWIRE_PREFS_FILE_NAME, Context.MODE_PRIVATE)

    /**
     * Whether a lock was configured, as far as anything that survives file deletion can tell.
     *
     * Fails towards [TripwireState.CONFIGURED] on tampering, and towards [TripwireState.UNREADABLE]
     * — not towards either answer — when the Keystore cannot be consulted at all. See
     * [TripwireState].
     */
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

    /** [tripwireState] collapsed to the question [tripwireBroken] asks. [TripwireState.UNREADABLE]
     *  answers false here — asserting "configured" off an unauthenticated file is the forged-marker
     *  wipe this class exists to prevent — and is handled instead by
     *  [LockedActivity], which refuses to open the app at all while the Keystore cannot be
     *  consulted. Answering it here in either direction is what made one branch defeatable and the
     *  other weaponisable. */
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
     *  configured. [SecurityWipe.enforceTripwire] turns this into a wipe at startup. */
    fun tripwireBroken(): Boolean = wasLockEnabled() && !prefs.contains(KEY_PIN_HASH)

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

        // Pre-pepper hash from an older install: verify against the v1 derivation, then upgrade in
        // place so the unpeppered value — which is offline-crackable in seconds for a 6-digit PIN —
        // stops existing on disk. Only ever upgrades on a *correct* PIN, so a wrong guess cannot
        // rewrite the verifier.
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

    /**
     * Writes the credential salt, and **refuses to overwrite an existing one**.
     *
     * A second write is always a bug: every secret already wrapped under the old salt becomes
     * permanently undecryptable the moment it lands. [AppLockManager] serialises the only two paths
     * that generate one, so this is unreachable — and it throws rather than logging, because
     * returning normally told the caller the salt had been persisted when it had not. The caller
     * then wrapped the device secret under a key nothing would ever reproduce, which is a worse
     * outcome than the crash.
     */
    override fun setCredentialSalt(salt: ByteArray) {
        check(!prefs.contains(KEY_CREDENTIAL_SALT)) { "Refusing to overwrite an existing credential salt" }
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
        // The durable half of the marker. Left behind, it says "a lock was configured" over a store
        // that no longer holds a PIN hash, which is exactly the tripwire condition — so turning the
        // lock off would arm a wipe for the next launch.
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

    /** See [openEncryptedPrefs]: resets only on an undecryptable keyset, never on a transient I/O
     *  failure. A reset here does NOT mean "no lock was ever set" — the plain tripwire above still
     *  says one was, and [SecurityWipe.enforceTripwire] destroys the cached data before it can be
     *  read. */
    private fun buildEncryptedPrefs(appContext: Context): SharedPreferences =
        openEncryptedPrefs(appContext, ENCRYPTED_PREFS_FILE_NAME) {
            android.util.Log.e(TAG, "Encrypted app-lock store keyset is undecryptable", it)
        }

    private companion object {
        /**
         * Serialises the failed-attempt read-modify-write across **every** instance.
         *
         * `private val` on the instance did not: [SecurityWipe] builds its own [AppLockStore], so
         * the two synchronised on two different monitors and serialised nothing — while the comment
         * here named that second instance as the reason the lock existed. A counter that feeds the
         * wipe threshold cannot be protected by a monitor that each holder gets a fresh copy of.
         *
         * Still process-scoped. If push ever moves to its own process, `SharedPreferences` offers
         * nothing here and this needs a file lock.
         */
        val counterLock = Any()
    }
}
