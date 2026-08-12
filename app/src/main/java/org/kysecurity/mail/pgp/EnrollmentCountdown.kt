package org.kysecurity.mail.pgp

/**
 * The countdown line's pure arithmetic, extracted so the wall-clock branch is a JVM test rather
 * than something only visible on a running screen. Kept free of Android imports for exactly that
 * reason — no `Context`, no `Resources`, nothing that needs an emulator to exercise.
 */
internal sealed class ExpiryCountdown {
    /** [remainingSeconds] is always > 0 — see [expiryCountdown]. */
    data class Counting(val remainingSeconds: Int) : ExpiryCountdown()

    /** The bucket has rolled, or is close enough that a one-second-granularity countdown cannot
     *  usefully distinguish it from having rolled. Covers the case a cancelled biometric prompt
     *  returns to a code whose expiry is already in the past: all of it renders "about to change"
     *  rather than a stale countdown or a negative number. */
    object Now : ExpiryCountdown()
}

/**
 * [nowMs] is a parameter rather than `System.currentTimeMillis()` read internally, so this is a
 * pure function a JVM test can drive directly.
 *
 * Integer division truncates toward zero, so a remainder under one second already reads as [Now]
 * up to 999ms before the bucket actually rolls. That is not a new source of error — the countdown
 * only ever had one-second granularity to begin with — but it is why "exactly 0" is one of this
 * function's required test cases rather than an incidental one.
 */
internal fun expiryCountdown(expiresAtEpochMs: Long, nowMs: Long): ExpiryCountdown {
    val remainingSeconds = (expiresAtEpochMs - nowMs) / 1_000L
    return if (remainingSeconds > 0) {
        ExpiryCountdown.Counting(remainingSeconds.toInt())
    } else {
        ExpiryCountdown.Now
    }
}
