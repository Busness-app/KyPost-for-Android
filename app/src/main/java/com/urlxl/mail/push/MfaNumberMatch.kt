package com.urlxl.mail.push

import kotlin.math.abs

/**
 * The number-matching choice set for one MFA challenge.
 *
 * A bare Approve button asks for a tap, and a tap is exactly what an MFA-fatigue attack harvests:
 * the user is woken at 03:00, has approved this same contentless prompt fifty times legitimately,
 * and taps. Number matching replaces the tap with a discrimination the user can only make if they
 * are looking at the screen that started the sign-in — which is what killed fatigue attacks for
 * Microsoft and Duo.
 *
 * Derived deterministically from the challenge id when the server does not supply decoys, so the
 * same challenge always renders the same options: `onNewIntent`, a recreate, or a return from the
 * biometric prompt must not reshuffle the buttons under the user's finger.
 *
 * Pure and Context-free so the selection logic is unit-testable on the JVM.
 */
internal object MfaNumberMatch {
    const val CHOICE_COUNT = 3

    /**
     * [correct] first is *not* the display order — [optionsFor] shuffles deterministically. Returns
     * null when the server supplied no [correct] value, meaning number matching is unavailable and
     * the caller must fall back to plain approve/deny.
     */
    fun optionsFor(challengeId: String, correct: String, serverDecoys: List<String>): List<String>? {
        if (correct.length != MfaChallengePayloadParser.MATCH_DIGITS_LENGTH) return null

        val decoys = (serverDecoys - correct).distinct().toMutableList()
        // Deterministic filler, seeded from the challenge id, when the server sent too few. Using
        // the id rather than a random source keeps the set stable across Activity recreation.
        var seed = challengeId.fold(7L) { acc, c -> acc * 31 + c.code }
        while (decoys.size < CHOICE_COUNT - 1) {
            seed = seed * 6364136223846793005L + 1442695040888963407L
            val candidate = (abs(seed / 65_536L) % 100L).toString().padStart(
                MfaChallengePayloadParser.MATCH_DIGITS_LENGTH,
                '0',
            )
            if (candidate != correct && candidate !in decoys) decoys += candidate
        }

        val choices = (decoys.take(CHOICE_COUNT - 1) + correct)
        // Stable shuffle: sort by a hash of (challengeId, value) so the correct answer is not
        // always in the same position, but the order never changes for a given challenge.
        return choices.sortedBy { value -> (challengeId + value).fold(17) { acc, c -> acc * 31 + c.code } }
    }
}
