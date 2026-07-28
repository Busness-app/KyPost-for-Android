package com.urlxl.mail.push

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "com.urlxl.mail.mfa_challenges"
private const val VALID_FOR_MS = 5 * 60 * 1000L

/**
 * Hard ceiling on tracked challenges.
 *
 * A relay that mints challenges faster than the user can answer them is the MFA-fatigue attack this
 * feature exists to resist, and the tracker used to grow one `commit()`-backed key per delivery with
 * no bound at all. Nobody legitimately has more than a couple of sign-ins in flight; past this,
 * the oldest entry is evicted.
 */
internal const val MAX_TRACKED_CHALLENGES = 8

/** The freshness window itself, split out from storage so it stays unit-testable on the JVM —
 *  a legitimate tap happens within moments of the notification arriving, never hours later. */
internal fun mfaChallengeIsFresh(deliveredAtEpochMs: Long, nowEpochMs: Long): Boolean =
    nowEpochMs - deliveredAtEpochMs in 0..VALID_FOR_MS

/**
 * Tracks challenge IDs that arrived via a real, decrypted push delivery (recorded by
 * [PushNotificationDispatcher.showMfaChallenge], and only once a notification for the challenge has
 * actually been posted). [MfaApprovalActivity] refuses any id that is not tracked, so a challenge
 * the user was never shown cannot be surfaced by anything that can start the activity — and
 * [MfaApprovalActivity.burnChallenge] uses the same mechanism in reverse to make a mis-tapped
 * challenge unanswerable.
 *
 * Persisted rather than held in a `ConcurrentHashMap`: FCM routinely delivers to a freshly-started
 * process and Android routinely kills that process again moments later, so an in-memory record was
 * usually gone by the time the user actually tapped the notification.
 *
 * Challenge IDs are not secrets (they authenticate nothing on their own; the server still requires
 * the device credential to act on one), so plain private SharedPreferences is the right storage —
 * an attacker who can write here already owns the app's sandbox.
 */
class MfaChallengeTracker(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Records [challengeId] and rewrites the file to the live, bounded set in ONE `commit()`.
     *
     * This used to be a `putLong` followed by a separate prune that materialised `prefs.all` and
     * issued a second `commit()` — two synchronous disk writes and a full map copy per delivery, on
     * the push-delivery thread, which a burst turned quadratic.
     */
    fun markDelivered(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()) {
        if (challengeId.isBlank()) return
        val survivors = liveEntries(nowEpochMs)
            .filterNot { it.first == challengeId }
            .sortedByDescending { it.second }
            .take(MAX_TRACKED_CHALLENGES - 1)
        prefs.edit().clear().apply {
            survivors.forEach { (id, deliveredAt) -> putLong(id, deliveredAt) }
            putLong(challengeId, nowEpochMs)
        }.commit()
    }

    fun isPending(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()): Boolean {
        if (challengeId.isBlank()) return false
        val deliveredAt = prefs.getLong(challengeId, -1L)
        if (deliveredAt < 0L) return false
        return mfaChallengeIsFresh(deliveredAt, nowEpochMs)
    }

    /** How many challenges are currently live. [PushNotificationDispatcher] uses this to stop
     *  posting a notification per challenge during a burst. */
    fun liveCount(nowEpochMs: Long = System.currentTimeMillis()): Int = liveEntries(nowEpochMs).size

    /** Called once a challenge has been answered, so a replayed notification tap can't re-open a
     *  decision the user already made. */
    fun clear(challengeId: String) {
        prefs.edit().remove(challengeId).commit()
    }

    private fun liveEntries(nowEpochMs: Long): List<Pair<String, Long>> =
        prefs.all.entries.mapNotNull { (id, value) ->
            (value as? Long)?.takeIf { mfaChallengeIsFresh(it, nowEpochMs) }?.let { id to it }
        }
}
