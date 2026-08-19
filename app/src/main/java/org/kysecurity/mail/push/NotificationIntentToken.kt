package org.kysecurity.mail.push

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

private const val PREFS_NAME = "org.kysecurity.mail.notification_intent"
private const val KEY_TOKEN = "token"
private const val TOKEN_BYTES = 32

/** Proof an Intent came from a notification this app posted; authenticity only, not replay. */
internal object NotificationIntentToken {

    /** Mints on first use and persists. */
    fun current(context: Context): String {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_TOKEN, null)?.let { return it }
        val fresh = ByteArray(TOKEN_BYTES).also { SecureRandom().nextBytes(it) }
        val encoded = Base64.encodeToString(fresh, Base64.NO_WRAP)
        // commit(): a PendingIntent minted against a token that never reached disk would stop
        // validating after the next process death, silently breaking notification taps.
        prefs.edit().putString(KEY_TOKEN, encoded).commit()
        return encoded
    }

    /** Constant-time comparison; false when no token has ever been minted. */
    fun matches(context: Context, candidate: String?): Boolean {
        if (candidate == null) return false
        val stored = context.applicationContext
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_TOKEN, null) ?: return false
        return MessageDigest.isEqual(
            stored.toByteArray(Charsets.UTF_8),
            candidate.toByteArray(Charsets.UTF_8),
        )
    }
}
