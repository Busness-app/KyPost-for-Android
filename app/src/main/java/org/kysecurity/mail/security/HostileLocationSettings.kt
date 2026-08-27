package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.security.MessageDigest

private const val KEY_ENABLED = "enabled"

/** HMAC over [KEY_ENABLED]'s value under [KeystoreHlpKey]; see [HostileLocationSettings.state]. */
private const val KEY_ENABLED_MAC = "enabled_mac"

private const val TAG = "HostileLocation"

enum class HostileLocationState {
    DISABLED,
    ENABLED,

    /** The Keystore could not be consulted, so neither answer above is knowable. */
    UNREADABLE,
}

/** Value plus HMAC under [KeystoreHlpKey]; tampering deliberately fails towards ENABLED. */
class HostileLocationSettings(context: Context) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Mirrors [AppLockStore.tripwireState] but fails the opposite way; keep them separate. */
    fun state(): HostileLocationState = synchronized(LOCK) {
        cached ?: readState().also { if (it != HostileLocationState.UNREADABLE) cached = it }
    }

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

    /** UNREADABLE answers true: callers decide where bytes go and have no wait-and-see. */
    fun isEnabled(): Boolean = state() != HostileLocationState.DISABLED

    /** Key first when enabling, marker first when disabling, so an interruption leaves it ON.
     *  Under [LOCK] because minting the key is slow: a read landing mid-enable used to resolve
     *  DISABLED and cache it for the life of the process. */
    fun setEnabled(enabled: Boolean) = synchronized(LOCK) {
        try {
            if (enabled) {
                KeystoreHlpKey.ensureExists()
                writeMarker(true)
            } else {
                prefs.edit().clear().commit()
                KeystoreHlpKey.destroy()
            }
        } finally {
            cached = null
        }
    }

    /** One byte, so the MAC covers the value and not merely the fact that a marker exists. */
    private fun payload(enabled: Boolean): ByteArray = byteArrayOf(if (enabled) 1 else 0)

    companion object {
        /** Named, not inlined: [SecurityWipe] has to retain this file through its final sweep. */
        internal const val PREFS_NAME = "org.kysecurity.mail.hostile_location_settings"

        /** Guards [cached] and every posture write, so no read sees a half-applied change. */
        private val LOCK = Any()

        /** Process-wide: one shared file. UNREADABLE is transient and never cached. */
        private var cached: HostileLocationState? = null
    }

    private fun writeMarker(enabled: Boolean) {
        val mac = KeystoreHlpKey.mix(payload(enabled))
        // commit(), like every other security-relevant write in this package: an async flush that
        // has not landed when the process dies would leave the posture and its MAC disagreeing.
        prefs.edit()
            .putBoolean(KEY_ENABLED, enabled)
            .putString(KEY_ENABLED_MAC, Base64.encodeToString(mac, Base64.NO_WRAP))
            .commit()
    }

    // No destroy(): SecurityWipe captures and restores the posture instead of tearing it down.
}
