package org.kysecurity.mail

/** Every ceiling on attacker-influenced heap, in one place; the sum is the number that matters. */
internal object MemoryBudget {

    /** Any single HTTP response body; [BodySizeLimitInterceptor] counts as it streams, so 1x. */
    const val RESPONSE_BYTES = 32L * 1024 * 1024

    /** One decrypted OpenPGP message; bound by the relay's 25 MB cap (~18 MB decoded). */
    const val PGP_PLAINTEXT_BYTES = 24 * 1024 * 1024

    /** 2x: `readAllWithLimit` holds the chunk list and the joined array at the same instant. */
    const val PGP_PLAINTEXT_PEAK_BYTES = 2L * PGP_PLAINTEXT_BYTES

    /** Decrypted attachments awaiting a viewer: the only retained term, so it sets the real peak. */
    const val PENDING_ATTACHMENT_BYTES = 32L * 1024 * 1024

    /** All three at once: 112 MB. Raising any constant raises this; it must fit a 128 MB heap. */
    const val WORST_CASE_PEAK_BYTES =
        RESPONSE_BYTES + PGP_PLAINTEXT_PEAK_BYTES + PENDING_ATTACHMENT_BYTES
}
