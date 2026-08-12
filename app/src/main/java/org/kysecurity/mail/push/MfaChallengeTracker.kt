package org.kysecurity.mail.push

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "org.kysecurity.mail.mfa_challenges"
private const val VALID_FOR_MS = 5 * 60 * 1000L

/** Not a challenge id — the alert-cooldown timestamp shares this file so the whole of MFA's
 *  anti-fatigue bookkeeping survives process death together. Filtered out of [liveEntries] by the
 *  same id validation that guards writes. */
private const val KEY_LAST_ALERT_AT = "!last_alert_at"

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
 *
 * **Every mutation runs under [lock], which is deliberately class-level rather than per-instance.**
 * [markDelivered] is a read-modify-write that rebuilds the whole file from a snapshot, and
 * [clear] removes a single key — so without serialisation, a `clear` landing between another
 * thread's read and its rewrite was silently undone. That is not a cosmetic race: it resurrects a
 * challenge the user has already burned by mis-tapping the number, or already answered and had
 * accepted by the server, breaking the "answered once, answerable once" property the whole screen
 * rests on. It fires exactly during a challenge flood, i.e. during the attack this resists. The
 * lock is class-level because these objects are still cheap to construct per call site and all of
 * them address the same file; per-instance locking would serialise nothing.
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
        // Re-validated here, not just at the parser: this id becomes a key in an XML file written
        // with commit() on the delivery thread, and `isBlank()` was the only thing standing between
        // a hostile relay and an arbitrary-length one. Defence at the point of persistence, so a
        // future caller that builds a payload some other way cannot reintroduce it.
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

    /**
     * The outcome of an alert-cooldown check.
     *
     * [previousAlertAtEpochMs] exists so a caller that ends up posting nothing can put the cooldown
     * back — see [restoreAlertCooldown].
     */
    data class AlertDecision(val suppress: Boolean, val previousAlertAtEpochMs: Long)

    /**
     * Whether the MFA notification's *sound* should be suppressed, advancing the cooldown when it
     * should not.
     *
     * Persisted, for the same reason the challenge records are: FCM routinely delivers to a
     * freshly-started process and kills it moments later. Holding this in a process-scoped `var`
     * meant the cooldown reset on every process churn — so under a real flood, which is the only
     * situation it exists for, every challenge alerted at IMPORTANCE_HIGH.
     *
     * The check and the advance stay in one locked section so two concurrent deliveries cannot both
     * decide to alert. A caller whose notification then fails to post calls [restoreAlertCooldown]
     * with [AlertDecision.previousAlertAtEpochMs]; rolling back afterwards is what keeps the
     * atomicity while still not spending a cooldown on an alert nobody heard.
     */
    fun shouldSuppressAlert(cooldownMs: Long, nowEpochMs: Long = System.currentTimeMillis()): AlertDecision =
        synchronized(lock) {
            val last = prefs.getLong(KEY_LAST_ALERT_AT, 0L)
            val suppress = last != 0L && nowEpochMs - last in 0..cooldownMs
            if (!suppress) prefs.edit().putLong(KEY_LAST_ALERT_AT, nowEpochMs).commit()
            AlertDecision(suppress = suppress, previousAlertAtEpochMs = last)
        }

    /**
     * Undoes [shouldSuppressAlert]'s advance when the notification it was for never reached the
     * shade — POST_NOTIFICATIONS revoked between the check and the post, or a `SecurityException`
     * on the way out.
     *
     * Without this, a delivery that showed the user nothing still silenced the next five minutes of
     * genuine sign-in prompts. [markDelivered] already refuses to record a challenge that was not
     * actually posted, for the same reason; the cooldown had been left out of that reasoning.
     */
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
