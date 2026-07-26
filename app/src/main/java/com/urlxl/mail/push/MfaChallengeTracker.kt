package com.urlxl.mail.push

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "com.urlxl.mail.mfa_challenges"
private const val VALID_FOR_MS = 5 * 60 * 1000L

/** The freshness window itself, split out from storage so it stays unit-testable on the JVM —
 *  a legitimate tap happens within moments of the notification arriving, never hours later. */
internal fun mfaChallengeIsFresh(deliveredAtEpochMs: Long, nowEpochMs: Long): Boolean =
    nowEpochMs - deliveredAtEpochMs in 0..VALID_FOR_MS

/**
 * Tracks challenge IDs that arrived via a real, decrypted push delivery (recorded by
 * [PushNotificationDispatcher.showMfaChallenge], called only from the messaging service's message
 * handler). [com.urlxl.mail.MainActivity] is exported as the app's launcher, so any co-installed
 * app can start it with arbitrary Intent extras; without this check, extras alone
 * (`type=mfa_challenge`, any `challengeId`) would be enough to surface the trusted-looking
 * approval screen for a challenge that was never actually pushed.
 *
 * Persisted rather than held in a `ConcurrentHashMap`: FCM routinely delivers to a freshly-started
 * process and Android routinely kills that process again moments later, so an in-memory record was
 * usually gone by the time the user actually tapped the notification — which sent them to the
 * inbox with no explanation while the sign-in they meant to approve timed out.
 *
 * Challenge IDs are not secrets (they authenticate nothing on their own; the server still requires
 * the device credential to act on one), so plain private SharedPreferences is the right storage —
 * an attacker who can write here already owns the app's sandbox.
 */
class MfaChallengeTracker(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun markDelivered(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()) {
        prefs.edit().putLong(challengeId, nowEpochMs).commit()
        prune(nowEpochMs)
    }

    fun isPending(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()): Boolean {
        if (challengeId.isBlank()) return false
        val deliveredAt = prefs.getLong(challengeId, -1L)
        if (deliveredAt < 0L) return false
        return mfaChallengeIsFresh(deliveredAt, nowEpochMs)
    }

    /** Called once a challenge has been answered, so a replayed notification tap can't re-open a
     *  decision the user already made. */
    fun clear(challengeId: String) {
        prefs.edit().remove(challengeId).commit()
    }

    private fun prune(nowEpochMs: Long) {
        val cutoff = nowEpochMs - VALID_FOR_MS
        val stale = prefs.all.filterValues { it is Long && it < cutoff }.keys
        if (stale.isEmpty()) return
        prefs.edit().apply { stale.forEach { remove(it) } }.commit()
    }
}
