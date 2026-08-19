package org.kysecurity.mail.pgp

/** The countdown line's pure arithmetic, kept Android-free so it is a JVM test. */
internal sealed class ExpiryCountdown {
    /** [remainingSeconds] is always > 0 — see [expiryCountdown]. */
    data class Counting(val remainingSeconds: Int) : ExpiryCountdown()

    /** The bucket has rolled, or is within a second of it: renders "about to change", never < 0. */
    object Now : ExpiryCountdown()
}

/** [nowMs] is a parameter so this is pure. Truncating division makes "exactly 0" a test case. */
internal fun expiryCountdown(expiresAtEpochMs: Long, nowMs: Long): ExpiryCountdown {
    val remainingSeconds = (expiresAtEpochMs - nowMs) / 1_000L
    return if (remainingSeconds > 0) {
        ExpiryCountdown.Counting(remainingSeconds.toInt())
    } else {
        ExpiryCountdown.Now
    }
}
