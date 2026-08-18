package org.kysecurity.mail.push

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

private const val PREFS_NAME = "org.kysecurity.mail.notification_intent"
private const val KEY_TOKEN = "token"
private const val TOKEN_BYTES = 32

/**
 * Proof that an Intent came from a notification this app posted.
 *
 * [org.kysecurity.mail.MainActivity] is `exported="true"` — it has to be, it holds the LAUNCHER
 * filter — and it forwarded three attacker-reachable extras straight into [InboxActivity]: a
 * message id, a sender and a subject. Any co-installed app, with no permissions at all, could
 * therefore drive the mail UI to an arbitrary message and put strings of its choosing on screen as
 * if they had arrived by mail. Splitting `PushPairingLinkActivity` out closed the same shape of
 * hole for the pairing screen; this closes it for the inbox.
 *
 * A stored random value rather than a per-notification nonce, because a `PendingIntent` outlives
 * the process that created it and has to keep validating after a cold start. It is an authenticity
 * marker, not a replay defence — the extras it protects are display-only. It cannot be read by
 * another app (the file is `MODE_PRIVATE`), and [org.kysecurity.mail.security.SecurityWipe]'s
 * shared-prefs sweep removes it, so stale PendingIntents from before a wipe stop validating.
 */
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
