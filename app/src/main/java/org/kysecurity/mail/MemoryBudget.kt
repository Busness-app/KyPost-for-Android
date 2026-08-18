package org.kysecurity.mail

/**
 * Every ceiling on attacker-influenced heap in this app, in one place, with the total stated.
 *
 * These were three constants in three files, each with its own well-argued paragraph and none
 * aware of the other two. Individually reasonable, they summed to 128 MB — on `minSdk 31`, with no
 * `android:largeHeap`, against devices whose per-app limit is routinely 128–192 MB. Nothing in the
 * source said so, because no file could see more than its own third of the number.
 *
 * **These are limits on retained size, and a limit is not a peak.** The first version of this file
 * summed the three limits and called the result the worst case. It is not: the PGP term
 * materialises an exact-length array out of an accumulator, so both exist at once and it peaks at
 * twice its limit. Every term below therefore states its own multiplier, and
 * [WORST_CASE_PEAK_BYTES] is built from the peaks rather than from the limits.
 *
 * **Deliberately static, not sized from `ActivityManager.getMemoryClass()`.** [PGP_PLAINTEXT_BYTES]
 * is consumed by [org.kysecurity.mail.pgp.PgpDecryptor], which has no Android imports on purpose so
 * the same code runs in a JVM test as on a device; threading a runtime-measured budget in would cost
 * that property to buy a number this app cannot act on anyway — there is no smaller mail to fetch.
 * The value here is that the sum is visible and reviewable when one of them changes.
 */
internal object MemoryBudget {

    /**
     * Any single HTTP response body. The streaming ceiling: reached transiently, and the largest
     * single allocation is the response being parsed.
     *
     * `/api/inbox` returns the full HTML body of every message in a folder and is the largest
     * response here; the attachment endpoint's own 25 MB cap sits under this one.
     *
     * Multiplier 1x: [org.kysecurity.mail.BodySizeLimitInterceptor] counts bytes as they stream and
     * throws at the bound, so the bytes never accumulate here — the caller's own materialisation is
     * what costs, and for the two callers that matter it is counted below rather than twice.
     */
    const val RESPONSE_BYTES = 32L * 1024 * 1024

    /**
     * One decrypted OpenPGP message.
     *
     * Lowered from 32 MB, and the reason is [PGP_PLAINTEXT_PEAK_BYTES] rather than caution: at
     * 32 MB this term alone peaked at 64 MB, which put the real total at 128 MB — the exact number
     * this file's own opening paragraph calls unacceptable. It was stated as 32.
     *
     * 24 MB still clears the case the old value was chosen for. An encrypted mail carries its
     * attachments inline and base64-inflated, so the binding constraint is the relay's 25 MB
     * attachment cap: 25 MB of base64 is ~18 MB decoded, and the surrounding MIME is small. A
     * message that genuinely exceeds this is refused with `TooLarge`, which is a path the UI
     * already has.
     */
    const val PGP_PLAINTEXT_BYTES = 24 * 1024 * 1024

    /**
     * What [PGP_PLAINTEXT_BYTES] actually costs at the instant it completes.
     *
     * `PgpDecryptor.readAllWithLimit` accumulates chunks and then joins them into an exact-length
     * array; both are live when the first chunk is copied. That 2x is irreducible for any strategy
     * that returns a `ByteArray` from a stream of unknown length — see that function's KDoc — so it
     * is stated here rather than hidden behind a limit that reads like a peak.
     */
    const val PGP_PLAINTEXT_PEAK_BYTES = 2L * PGP_PLAINTEXT_BYTES

    /**
     * Total decrypted attachment plaintext parked awaiting a viewer's read.
     *
     * The one that came down first, from 64 MB. Unlike the two above this is *retained* — for up to
     * a minute, across several attachments, while the other two are transient — so it is the term
     * that decides the realistic peak. 32 MB still holds one attachment at the 25 MB relay cap,
     * which is the case that has to work; past that
     * [org.kysecurity.mail.security.EphemeralAttachmentBytes.register] refuses, and the caller
     * already has a "cannot serve this" path.
     *
     * Multiplier 1x: the bytes arrive already materialised and are stored by reference.
     */
    const val PENDING_ATTACHMENT_BYTES = 32L * 1024 * 1024

    /**
     * Worst case if all three are at their ceiling at once: 32 + 48 + 32 = **112 MB**.
     *
     * Reachable, and all three genuinely overlap — a large attachment parked for viewing (from an
     * earlier decrypt) while a big inbox refresh streams on the mail executor and a second PGP
     * message opens on `Dispatchers.Default`. Treat it as the number, not as a theoretical sum.
     *
     * It is over the 96 MB the previous version of this file claimed, because that figure was
     * arrived at by summing limits rather than peaks. 112 MB is what the app has always cost; only
     * the arithmetic changed. It fits a 128 MB heap with little room and a 192 MB heap comfortably,
     * which is the honest statement — and it is why [PGP_PLAINTEXT_BYTES] came down rather than the
     * total being written up.
     *
     * Raising any constant above means raising this, and this is the one that has to stay under a
     * mid-range device's heap.
     */
    const val WORST_CASE_PEAK_BYTES =
        RESPONSE_BYTES + PGP_PLAINTEXT_PEAK_BYTES + PENDING_ATTACHMENT_BYTES
}
