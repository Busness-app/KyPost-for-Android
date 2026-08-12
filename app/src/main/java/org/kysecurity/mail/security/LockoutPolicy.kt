package org.kysecurity.mail.security

/**
 * Escalating-delay + eventual-wipe lockout curve for wrong app-lock PIN attempts (see
 * "Require Unlock to Open" in the 2026-07-22 security-hardening spec). Attempts 1-2 are free
 * (typos happen); attempt 3 onward adds a growing delay before the next try is allowed;
 * [WIPE_THRESHOLD] consecutive wrong attempts (no intervening correct PIN/biometric) wipes
 * local data via [SecurityWipe].
 */
object LockoutPolicy {
    private val DELAYS_MS = longArrayOf(30_000L, 60_000L, 300_000L, 900_000L, 1_800_000L)
    private const val FIRST_DELAYED_ATTEMPT = 3
    const val WIPE_THRESHOLD = 10

    fun delayMillisFor(attemptCount: Int): Long {
        if (attemptCount < FIRST_DELAYED_ATTEMPT) return 0L
        val index = (attemptCount - FIRST_DELAYED_ATTEMPT).coerceAtMost(DELAYS_MS.size - 1)
        return DELAYS_MS[index]
    }

    fun shouldWipe(attemptCount: Int): Boolean = attemptCount >= WIPE_THRESHOLD
}
