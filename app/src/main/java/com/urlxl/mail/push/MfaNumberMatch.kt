package com.urlxl.mail.push

/**
 * The number-matching choice set for one MFA challenge.
 *
 * A bare Approve button asks for a tap, and a tap is exactly what an MFA-fatigue attack harvests.
 * Number matching replaces it with a discrimination the user can only make if they are looking at
 * the screen that started the sign-in.
 *
 * **Every value comes from the server.** The client used to invent decoys from a linear congruential
 * generator seeded on the challenge id when the server sent too few, which made the wrong answers
 * derivable by anyone who knew the id. The server mints the correct value and both decoys from
 * `crypto/rand` (kypost-server `mfa.newNumberMatch`), and it verifies the answer itself
 * (`Store.ResolvePushWithMatch`) — so a challenge that does not carry all three is one this client
 * cannot offer an approval for at all. [optionsFor] returns null there, and the caller must leave
 * only Deny available rather than falling back to a button the server will refuse.
 *
 * Digit width is whatever the server used, not a hardcoded 2. The width was pinned in three places
 * across two repositories with no negotiation, so widening the server's value space — the obvious
 * next hardening, since two digits is only 100 values — would have silently disabled approval on
 * every deployed client.
 *
 * Pure and Context-free so the selection logic is unit-testable on the JVM.
 */
internal object MfaNumberMatch {
    const val CHOICE_COUNT = 3

    /**
     * The tiles to render, in the order to render them, or null when [correct] and [serverDecoys]
     * do not describe a complete [CHOICE_COUNT]-way choice.
     *
     * Order is randomised per call. [shuffle] is injectable only so tests can pin it; callers must
     * shuffle **once** and keep the result for the life of the challenge, or a recreate would
     * reorder the tiles under the user's finger — see [MfaApprovalActivity].
     */
    fun optionsFor(
        correct: String,
        serverDecoys: List<String>,
        shuffle: (List<String>) -> List<String> = { it.shuffled() },
    ): List<String>? {
        if (!MfaChallengePayloadParser.isValidMatchDigits(correct)) return null
        val decoys = serverDecoys
            .filter { it != correct && it.length == correct.length }
            .distinct()
        // Exactly, not at least: fewer is an incomplete challenge, and more means the server and
        // this client disagree about the shape of the choice.
        if (decoys.size != CHOICE_COUNT - 1) return null
        return shuffle(decoys + correct)
    }
}
