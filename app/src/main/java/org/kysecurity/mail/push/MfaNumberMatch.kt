package org.kysecurity.mail.push

/** Server-minted number-match choices; null from [optionsFor] means approval is impossible. */
internal object MfaNumberMatch {
    const val CHOICE_COUNT = 3

    /** Null when the choice is incomplete. Callers must shuffle once and keep the order. */
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
