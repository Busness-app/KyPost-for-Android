package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.security.MessageDigest

private const val PREFS_NAME = "org.kysecurity.mail.hostile_location_settings"
private const val KEY_ENABLED = "enabled"

/** HMAC over [KEY_ENABLED]'s value under [KeystoreHlpKey]; see [HostileLocationSettings.state]. */
private const val KEY_ENABLED_MAC = "enabled_mac"

private const val TAG = "HostileLocation"

/**
 * What the protection flag can actually say, which is three things rather than two — the same shape
 * and the same reasoning as [TripwireState].
 */
enum class HostileLocationState {
    DISABLED,
    ENABLED,

    /** The Keystore could not be consulted, so neither answer above is knowable. */
    UNREADABLE,
}

/**
 * Whether Hostile Location Protection is on: no database file, no persisted push history, no
 * attachment ever written to disk.
 *
 * **Authenticated, because of what reads it.** This was a bare `Boolean` in a `MODE_PRIVATE`
 * preferences file — the exact primitive [KeystoreTripwireKey]'s KDoc spends a paragraph proving is
 * not a control — while being the single flag that decides whether the user's mail exists on disk
 * at all. The app-lock tripwire got a Keystore anchor over a much smaller claim; this one had
 * nothing, and its own test asserted only that the default is false and that it persists, because
 * there was nothing else to assert.
 *
 * The marker is now a value plus an HMAC under [KeystoreHlpKey], and the key's mere presence is the
 * durable half: deleting both preference files no longer silently downgrades the posture, and
 * writing `enabled=false` into the file no longer does either.
 *
 * **Tampering fails towards [HostileLocationState.ENABLED]**, the opposite of the app lock's
 * tripwire and for the mirror-image reason. There, failing towards "configured" would destroy data;
 * here, failing towards "disabled" would start writing plaintext to a disk the user believes is
 * empty. The cost of the safe answer is that cached mail is unavailable until it resolves.
 */
class HostileLocationSettings(context: Context) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Memoised per instance, because this is on hot paths that the old plain-boolean read was free
     * on: [org.kysecurity.mail.mail.MailCursorStore] consults it per cursor operation, and
     * [org.kysecurity.mail.data.DataGraph] at construction. A Keystore round trip each time would
     * be a real regression, and the same precedent is already set by
     * [org.kysecurity.mail.push.SecurePairingStore]'s cached TLS pin.
     *
     * Safe because the threat is a file edited *between* processes, not during one: every
     * legitimate write goes through [setEnabled], which clears this, and every write is followed by
     * [AppRestart.relaunch] rebuilding the graphs that hold these instances. [UNREADABLE] is
     * deliberately NOT memoised — it is a transient device condition, and caching it would keep the
     * app blocked past the keystore2 restart that caused it.
     */
    @Volatile
    private var memo: HostileLocationState? = null

    /**
     * The posture, or that it cannot be determined.
     *
     * Mirrors [AppLockStore.tripwireState] step for step; keep the two in sync by hand, because the
     * *directions they fail in are deliberately opposite* and a shared implementation would invite
     * someone to unify that away.
     */
    fun state(): HostileLocationState = memo ?: readState().also { if (it != HostileLocationState.UNREADABLE) memo = it }

    private fun readState(): HostileLocationState {
        val claimed = prefs.getBoolean(KEY_ENABLED, false)
        val storedMac = prefs.getString(KEY_ENABLED_MAC, null)

        val keyPresent = try {
            KeystoreHlpKey.exists()
        } catch (e: PepperUnavailableException) {
            Log.e(TAG, "Could not consult the protection key", e)
            return HostileLocationState.UNREADABLE
        }
        // No key has ever existed, so protection has never been enabled. This is the fresh-install
        // path and it must NOT read as tampering, or every new install would block on first launch.
        if (!keyPresent) return HostileLocationState.DISABLED

        if (storedMac == null) {
            Log.e(TAG, "Protection key exists but its marker is gone; treating as tampering")
            return HostileLocationState.ENABLED
        }
        val expected = runCatching { KeystoreHlpKey.mix(payload(claimed)) }.getOrNull()
        if (expected == null) {
            Log.e(TAG, "Protection marker could not be recomputed; treating as tampering")
            return HostileLocationState.ENABLED
        }
        val actual = runCatching { Base64.decode(storedMac, Base64.NO_WRAP) }.getOrNull()
        if (actual == null || !MessageDigest.isEqual(expected, actual)) {
            Log.e(TAG, "Protection marker failed authentication; treating as tampering")
            return HostileLocationState.ENABLED
        }
        return if (claimed) HostileLocationState.ENABLED else HostileLocationState.DISABLED
    }

    /**
     * [state] collapsed to the question every consumer actually asks.
     *
     * [HostileLocationState.UNREADABLE] answers **true** here. Every caller of this decides where
     * bytes go — an in-memory database or a file, an ephemeral pipe or shared Downloads — and there
     * is no "wait and see" available at those call sites. Answering true means the app is
     * temporarily less useful; answering false means it writes plaintext the user believes is not
     * being written. [LockedActivity] is what turns the unreadable case into something the user is
     * actually told about.
     */
    fun isEnabled(): Boolean = state() != HostileLocationState.DISABLED

    /**
     * Writes the flag, minting or destroying [KeystoreHlpKey] to match.
     *
     * **Key first when enabling**, exactly as [AppLockStore.enableLock] does: a marker written
     * before the key that authenticates it exists cannot be verified, and [state] reads an
     * unverifiable marker as tampering.
     *
     * **Marker first, key last when disabling.** Every interruption point then leaves protection
     * ON — after the clear, the key is still present with no marker beside it, which [state] reads
     * as tampering and answers ENABLED — so a process death during a disable is a retry rather than
     * a silent downgrade.
     *
     * Disabling deliberately writes no `enabled = false` marker on the way out. It cannot: MACing
     * one needs the key, and `setEnabled(false)` is reachable on a device that never enabled
     * protection at all — `SecuritySettingsActivity.disableLock` calls it unconditionally — where
     * [KeystoreHlpKey.mix] would throw [PepperUnavailableException]. It also would not buy
     * anything: "no key, no marker" already IS the disabled state, and it is the same state a fresh
     * install is in.
     */
    fun setEnabled(enabled: Boolean) {
        memo = null
        if (enabled) {
            KeystoreHlpKey.ensureExists()
            writeMarker(true)
            return
        }
        prefs.edit().clear().commit()
        KeystoreHlpKey.destroy()
    }

    /** One byte, so the MAC covers the value and not merely the fact that a marker exists. */
    private fun payload(enabled: Boolean): ByteArray = byteArrayOf(if (enabled) 1 else 0)

    private fun writeMarker(enabled: Boolean) {
        val mac = KeystoreHlpKey.mix(payload(enabled))
        // commit(), like every other security-relevant write in this package: an async flush that
        // has not landed when the process dies would leave the posture and its MAC disagreeing.
        prefs.edit()
            .putBoolean(KEY_ENABLED, enabled)
            .putString(KEY_ENABLED_MAC, Base64.encodeToString(mac, Base64.NO_WRAP))
            .commit()
    }

    // Deliberately no `destroy()` teardown helper alongside the other security stores. SecurityWipe
    // does not tear this down: it captures the posture before wiping and RESTORES it afterwards,
    // because a wipe that runs because the device is presumed hostile must not switch off the
    // feature for that exact situation. `setEnabled(false)` is the only path that removes the key.
}
