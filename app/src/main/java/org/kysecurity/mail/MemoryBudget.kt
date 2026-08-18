package org.kysecurity.mail

/**
 * Every ceiling on attacker-influenced heap in this app, in one place, with the total stated.
 *
 * They live together because the sum is the number that matters: `minSdk 31`, no
 * `android:largeHeap`, and per-app limits routinely 128–192 MB. Split across three files, no one of
 * them could see more than its own third.
 *
 * **A limit is not a peak.** Some terms cost more than their bound at the instant they complete, so
 * each states its own multiplier and [WORST_CASE_PEAK_BYTES] is built from the peaks.
 *
 * **Static, not sized from `ActivityManager.getMemoryClass()`.** [PGP_PLAINTEXT_BYTES] is consumed
 * by [org.kysecurity.mail.pgp.PgpDecryptor], which has no Android imports so the same code runs in
 * a JVM test as on a device. There is also no smaller mail to fetch, so a runtime-measured budget
 * would buy a number the app cannot act on.
 */
internal object MemoryBudget {

    /**
     * Any single HTTP response body. `/api/inbox` returns the full HTML body of every message in a
     * folder and is the largest response here; the attachment endpoint's own 25 MB cap sits under
     * this one.
     *
     * Multiplier 1x: [org.kysecurity.mail.BodySizeLimitInterceptor] counts bytes as they stream and
     * throws at the bound, so they never accumulate here. What the caller then materialises is
     * counted below rather than twice.
     */
    const val RESPONSE_BYTES = 32L * 1024 * 1024

    /**
     * One decrypted OpenPGP message.
     *
     * An encrypted mail carries its attachments inline and base64-inflated, so the binding
     * constraint is the relay's 25 MB attachment cap: 25 MB of base64 is ~18 MB decoded, and the
     * surrounding MIME is small. A message that exceeds this is refused with `TooLarge`, a path the
     * UI already has.
     */
    const val PGP_PLAINTEXT_BYTES = 24 * 1024 * 1024

    /**
     * What [PGP_PLAINTEXT_BYTES] costs at the instant it completes.
     *
     * `PgpDecryptor.readAllWithLimit` accumulates chunks and then joins them into an exact-length
     * array; both are live when the first chunk is copied. That 2x is irreducible for any strategy
     * returning a `ByteArray` from a stream of unknown length, so it is stated rather than hidden
     * behind a limit that reads like a peak.
     */
    const val PGP_PLAINTEXT_PEAK_BYTES = 2L * PGP_PLAINTEXT_BYTES

    /**
     * Total decrypted attachment plaintext parked awaiting a viewer's read.
     *
     * The only *retained* term — up to a minute, across several attachments, while the other two are
     * transient — so it decides the realistic peak. 32 MB holds one attachment at the 25 MB relay
     * cap, which is the case that has to work; past that
     * [org.kysecurity.mail.security.EphemeralAttachmentBytes.register] refuses and the caller has a
     * "cannot serve this" path.
     *
     * Multiplier 1x: the bytes arrive already materialised and are stored by reference.
     */
    const val PENDING_ATTACHMENT_BYTES = 32L * 1024 * 1024

    /**
     * All three at their ceiling at once: 32 + 48 + 32 = **112 MB**.
     *
     * Reachable, and they genuinely overlap — an attachment parked for viewing from an earlier
     * decrypt, a big inbox refresh streaming on the mail executor, a second PGP message opening on
     * `Dispatchers.Default`. It fits a 128 MB heap with little room and a 192 MB heap comfortably.
     *
     * Raising any constant above means raising this, and this is the one that has to stay under a
     * mid-range device's heap.
     */
    const val WORST_CASE_PEAK_BYTES =
        RESPONSE_BYTES + PGP_PLAINTEXT_PEAK_BYTES + PENDING_ATTACHMENT_BYTES
}
