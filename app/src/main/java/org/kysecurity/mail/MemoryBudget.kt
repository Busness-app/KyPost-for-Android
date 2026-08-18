package org.kysecurity.mail

/**
 * Every ceiling on attacker-influenced heap in this app, in one place, with the total stated.
 *
 * These were three constants in three files, each with its own well-argued paragraph and none
 * aware of the other two. Individually reasonable, they summed to 128 MB — on `minSdk 31`, with no
 * `android:largeHeap`, against devices whose per-app limit is routinely 128–192 MB. Nothing in the
 * source said so, because no file could see more than its own third of the number.
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
     */
    const val RESPONSE_BYTES = 32L * 1024 * 1024

    /**
     * One decrypted OpenPGP message.
     *
     * Not lowered despite being the largest of the three, and the reason is a real constraint
     * rather than caution: an encrypted mail carries its attachments inline and base64-inflated, so
     * a 25 MB attachment is ~34 MB of plaintext. The ciphertext arrives through
     * [RESPONSE_BYTES] anyway, which is the ceiling that actually bounds this one.
     */
    const val PGP_PLAINTEXT_BYTES = 32 * 1024 * 1024

    /**
     * Total decrypted attachment plaintext parked awaiting a viewer's read.
     *
     * The one that came down, from 64 MB. Unlike the two above this is *retained* — for up to a
     * minute, across several attachments, while the other two are transient — so it is the term
     * that decides the realistic peak. 32 MB still holds one attachment at the 25 MB relay cap,
     * which is the case that has to work; past that
     * [org.kysecurity.mail.security.EphemeralAttachmentBytes.register] refuses, and the caller
     * already has a "cannot serve this" path.
     */
    const val PENDING_ATTACHMENT_BYTES = 32L * 1024 * 1024

    /**
     * Worst case if all three are at their ceiling at once: 96 MB. Reachable — a large attachment
     * parked for viewing while a big inbox refresh streams and a PGP message opens — so treat it as
     * the number, not as a theoretical sum. Raising any constant above means raising this, and
     * this is the one that has to stay under a mid-range device's heap.
     */
    const val WORST_CASE_TOTAL_BYTES =
        RESPONSE_BYTES + PGP_PLAINTEXT_BYTES + PENDING_ATTACHMENT_BYTES
}
