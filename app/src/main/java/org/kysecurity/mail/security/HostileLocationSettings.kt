package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "org.kysecurity.mail.hostile_location_settings"
private const val KEY_ENABLED = "enabled"

/**
 * Whether Hostile Location Protection is on (see the 2026-07-22 security-hardening spec) — a
 * plain, unencrypted flag (not a secret) that [org.kysecurity.mail.data.DataGraph] reads at Room
 * construction time to decide disk-backed vs in-memory-only storage.
 */
class HostileLocationSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        // commit(), not apply(), like every other security-relevant write in this package: this
        // flag decides whether Room is disk-backed, and it is written *after* the on-disk database
        // has already been deleted. A process death before an async flush would have reverted
        // protection to off while the user believed it was on.
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }
}
