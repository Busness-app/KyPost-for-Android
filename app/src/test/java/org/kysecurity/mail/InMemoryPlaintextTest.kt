package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPlaintextTest {

    @After
    fun tearDown() {
        InMemoryPlaintext.clearAll()
    }

    private fun attachment() = OutgoingAttachment(
        name = "statement.pdf",
        mimeType = "application/pdf",
        dataBase64 = "SGVsbG8=",
        size = 5,
    )

    private fun draft() = CachedDraft(
        to = "recipient@example.com",
        cc = "",
        bcc = "",
        subject = "Confidential",
        bodyHtml = "<p>account number 12345</p>",
        attachments = listOf(attachment()),
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

    @Test
    fun clearAllDropsBothInOnePass() {
        ComposeDraftCache.save(draft())
        ForwardAttachmentHandoff.put(listOf(attachment()))

        InMemoryPlaintext.clearAll()

        assertNull(ComposeDraftCache.take())
        assertTrue(ForwardAttachmentHandoff.take().isEmpty())
    }
}
