package org.kysecurity.mail.security

/**
 * Escalating-delay + optional-wipe lockout curve for wrong app-lock PIN attempts (see
 * "Require Unlock to Open" in the 2026-07-22 security-hardening spec). Attempts 1-2 are free
 * (typos happen); attempt 3 onward adds a growing delay before the next try is allowed; once
 * [wipeAfterAttempts] consecutive wrong attempts accumulate (no intervening correct PIN/biometric)
 * local data is wiped via [SecurityWipe].
 *
 * **The wipe is a user choice, and the ladder is long enough to be one.** It used to be a
 * hardcoded ten attempts with no way to turn it off, over a ladder summing to about eighty
 * minutes. That is not a defence — an attacker wants to read the mailbox, not delete it — but it
 * is a very effective denial of service: anyone who borrows the phone for an afternoon, or a child
 * who finds the PIN screen entertaining, destroys mail and contacts that `allowBackup="false"` and
 * `data_extraction_rules.xml` deliberately make unrecoverable. The ladder below tops out at an
 * hour per attempt so reaching the threshold takes most of a day rather than a lunch break, and
 * [AppLockSettings] lets the user pick the threshold or turn the wipe off entirely.
 */
object LockoutPolicy {
    private val DELAYS_MS = longArrayOf(
        30_000L,
        60_000L,
        300_000L,
        900_000L,
        1_800_000L,
        3_600_000L,
    )
    private const val FIRST_DELAYED_ATTEMPT = 3

    /** Offered in the settings UI. Null means "never wipe". */
    val WIPE_THRESHOLD_CHOICES = listOf(10, 20, 30)

    /** What a fresh install gets: on, and at the most forgiving end of the offered range. */
    const val DEFAULT_WIPE_THRESHOLD = 30

    fun delayMillisFor(attemptCount: Int): Long {
        if (attemptCount < FIRST_DELAYED_ATTEMPT) return 0L
        val index = (attemptCount - FIRST_DELAYED_ATTEMPT).coerceAtMost(DELAYS_MS.size - 1)
        return DELAYS_MS[index]
    }

    /** @param wipeAfterAttempts null when the user has turned the wipe off. */
    fun shouldWipe(attemptCount: Int, wipeAfterAttempts: Int?): Boolean =
        wipeAfterAttempts != null && attemptCount >= wipeAfterAttempts

    /** How long reaching [wipeAfterAttempts] actually takes, so the settings screen can state it
     *  rather than leaving the user to infer it from a number of attempts. */
    fun timeToWipeMillis(wipeAfterAttempts: Int): Long =
        (1..wipeAfterAttempts).sumOf { delayMillisFor(it) }
}
