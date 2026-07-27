package com.urlxl.mail

import com.urlxl.mail.mail.OutgoingAttachment
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The security wipe and the account purge both have to destroy message plaintext that never
 * reaches disk. Neither can be unit-tested directly (one is Android-only, the other needs Room),
 * so the shared clear is a plain function and this is where it is pinned.
 */
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
