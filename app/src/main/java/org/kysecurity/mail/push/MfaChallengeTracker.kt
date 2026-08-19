package org.kysecurity.mail.push

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "org.kysecurity.mail.mfa_challenges"
private const val VALID_FOR_MS = 5 * 60 * 1000L

/** Not a challenge id: the alert cooldown shares this file. Filtered out of [liveEntries]. */
private const val KEY_LAST_ALERT_AT = "!last_alert_at"

/** Hard ceiling on tracked challenges. */
internal const val MAX_TRACKED_CHALLENGES = 8

/** The freshness window itself, split out from storage so it stays unit-testable on the JVM —
 *  a legitimate tap happens within moments of the notification arriving, never hours later. */
internal fun mfaChallengeIsFresh(deliveredAtEpochMs: Long, nowEpochMs: Long): Boolean =
    nowEpochMs - deliveredAtEpochMs in 0..VALID_FOR_MS

/** Ids from real pushes only. Persisted; every mutation runs under the class-level [lock]. */
class MfaChallengeTracker(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Records [challengeId] and rewrites the file to the live, bounded set in ONE `commit()`. */
    fun markDelivered(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()) {
        // Re-validated at the point of persistence: this id becomes a key in an XML file.
        if (!MfaChallengePayloadParser.isValidChallengeId(challengeId)) return
        synchronized(lock) {
            val survivors = liveEntries(nowEpochMs)
                .filterNot { it.first == challengeId }
                .sortedByDescending { it.second }
                .take(MAX_TRACKED_CHALLENGES - 1)
            val lastAlertAt = prefs.getLong(KEY_LAST_ALERT_AT, 0L)
            prefs.edit().clear().apply {
                survivors.forEach { (id, deliveredAt) -> putLong(id, deliveredAt) }
                putLong(challengeId, nowEpochMs)
                // Carried across the clear(): the cooldown lives in this file and must not be
                // reset by an unrelated delivery, or a flood re-alerts on every challenge.
                if (lastAlertAt != 0L) putLong(KEY_LAST_ALERT_AT, lastAlertAt)
            }.commit()
        }
    }

    fun isPending(challengeId: String, nowEpochMs: Long = System.currentTimeMillis()): Boolean {
        if (!MfaChallengePayloadParser.isValidChallengeId(challengeId)) return false
        val deliveredAt = synchronized(lock) { prefs.getLong(challengeId, -1L) }
        if (deliveredAt < 0L) return false
        return mfaChallengeIsFresh(deliveredAt, nowEpochMs)
    }

    /** How many challenges are currently live. [PushNotificationDispatcher] uses this to stop
     *  posting a notification per challenge during a burst. */
    fun liveCount(nowEpochMs: Long = System.currentTimeMillis()): Int =
        synchronized(lock) { liveEntries(nowEpochMs).size }

    /** Called once a challenge has been answered, so a replayed notification tap can't re-open a
     *  decision the user already made. */
    fun clear(challengeId: String) {
        synchronized(lock) { prefs.edit().remove(challengeId).commit() }
    }

    /** [previousAlertAtEpochMs] lets a caller that posts nothing put the cooldown back. */
    data class AlertDecision(val suppress: Boolean, val previousAlertAtEpochMs: Long)

    /** Persisted across process churn; the check and the advance stay in one locked section. */
    fun shouldSuppressAlert(cooldownMs: Long, nowEpochMs: Long = System.currentTimeMillis()): AlertDecision =
        synchronized(lock) {
            val last = prefs.getLong(KEY_LAST_ALERT_AT, 0L)
            val suppress = last != 0L && nowEpochMs - last in 0..cooldownMs
            if (!suppress) prefs.edit().putLong(KEY_LAST_ALERT_AT, nowEpochMs).commit()
            AlertDecision(suppress = suppress, previousAlertAtEpochMs = last)
        }

    /** Undoes [shouldSuppressAlert]'s advance when the notification never reached the shade. */
    fun restoreAlertCooldown(previousAlertAtEpochMs: Long) {
        synchronized(lock) {
            val editor = prefs.edit()
            if (previousAlertAtEpochMs == 0L) {
                editor.remove(KEY_LAST_ALERT_AT)
            } else {
                editor.putLong(KEY_LAST_ALERT_AT, previousAlertAtEpochMs)
            }
            editor.commit()
        }
    }

    /** Callers hold [lock]. */
    private fun liveEntries(nowEpochMs: Long): List<Pair<String, Long>> =
        prefs.all.entries.mapNotNull { (id, value) ->
            if (!MfaChallengePayloadParser.isValidChallengeId(id)) return@mapNotNull null
            (value as? Long)?.takeIf { mfaChallengeIsFresh(it, nowEpochMs) }?.let { id to it }
        }

    private companion object {
        /** See the class KDoc: shared by every instance, because every instance is the same file. */
        val lock = Any()
    }
}
