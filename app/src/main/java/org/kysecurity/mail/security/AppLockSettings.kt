package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "org.kysecurity.mail.app_lock_settings"
private const val KEY_GRACE_MILLIS = "lock_grace_millis"

/**
 * How long the app may stay backgrounded before the app lock re-engages.
 *
 * A plain, unencrypted preference rather than part of [AppLockStore]: it is not a secret, and it is
 * read from `Application.onStop`, which must not touch the Keystore on the main thread.
 */
class AppLockSettings(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun graceMillis(): Long = prefs.getLong(KEY_GRACE_MILLIS, DEFAULT_GRACE_MILLIS)

    fun setGraceMillis(millis: Long) {
        // commit(), like every other security-relevant write in this package: a process death
        // before an async flush would silently leave the previous window in force.
        prefs.edit().putLong(KEY_GRACE_MILLIS, millis.coerceIn(0L, MAX_GRACE_MILLIS)).commit()
    }

    companion object {
        /** Long enough for a file-picker or chooser round trip, short enough that a pocketed
         *  phone re-locks before anyone picks it up. */
        const val DEFAULT_GRACE_MILLIS = 30_000L
        const val MAX_GRACE_MILLIS = 300_000L

        /** The choices offered in Security settings, longest-lived first in the UI. */
        val OPTIONS_MILLIS = longArrayOf(0L, 30_000L, 60_000L, 300_000L)
    }
}
