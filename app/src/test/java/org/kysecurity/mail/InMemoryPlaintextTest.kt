package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPlaintextTest {

    /** [ComposeDraftCache] is process-wide and `clearAll` SEALS it; only `take()` unseals. Leaving
     *  it sealed silently turns the next test class's `save()` into a no-op, which is an
     *  order-dependent failure in a file that never mentions this cache. */
    @After
    fun tearDown() {
        InMemoryPlaintext.clearAll()
        ComposeDraftCache.take()
    }

    private fun attachment() = OutgoingAttachment(
        name = "statement.pdf",
        mimeType = "application/pdf",
        bytes = "Hello".toByteArray(Charsets.UTF_8),
    )

    private fun draft(attachments: List<OutgoingAttachment> = listOf(attachment())) = CachedDraft(
        to = "recipient@example.com",
        cc = "",
        bcc = "",
        subject = "Confidential",
        bodyHtml = "<p>account number 12345</p>",
        attachments = attachments,
    )

    @Test
    fun clearAllDropsACachedComposeDraft() {
        ComposeDraftCache.save(draft())

        InMemoryPlaintext.clearAll()

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun clearAllDropsPendingForwardAttachments() {
        ForwardAttachmentHandoff.put(listOf(attachment()))

        InMemoryPlaintext.clearAll()

        assertTrue(ForwardAttachmentHandoff.take().isEmpty())
    }

    /** Dropping a reference is not erasing it: the bytes stay readable in a heap dump until the
     *  collector runs, and possibly after. This is the property that only became reachable when
     *  `OutgoingAttachment` stopped holding base64 in a `String`, which cannot be overwritten. */
    @Test
    fun clearAllZeroesACachedDraftsAttachmentBytes() {
        val held = attachment()
        assertTrue("precondition: the attachment carries plaintext", held.bytes.any { it != 0.toByte() })
        ComposeDraftCache.save(draft(listOf(held)))

        InMemoryPlaintext.clearAll()

        assertTrue(
            "attachment plaintext survived a session reset",
            held.bytes.all { it == 0.toByte() },
        )
    }

    @Test
    fun clearAllZeroesPendingForwardAttachmentBytes() {
        val held = attachment()
        ForwardAttachmentHandoff.put(listOf(held))

        InMemoryPlaintext.clearAll()

        assertTrue(
            "forward-handoff plaintext survived a session reset",
            held.bytes.all { it == 0.toByte() },
        )
    }

    @Test
    fun clearAllDropsBothInOnePass() {
        ComposeDraftCache.save(draft())
        ForwardAttachmentHandoff.put(listOf(attachment()))

        InMemoryPlaintext.clearAll()

        assertNull(ComposeDraftCache.take())
        assertTrue(ForwardAttachmentHandoff.take().isEmpty())
    }
}
