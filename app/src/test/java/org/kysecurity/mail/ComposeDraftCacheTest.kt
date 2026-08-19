package org.kysecurity.mail

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.mail.OutgoingAttachment

class ComposeDraftCacheTest {

    /** The cache is process-wide: clear() seals it, and only take() unseals for the next test. */
    @After
    fun tearDown() {
        ComposeDraftCache.clear()
        ComposeDraftCache.take()
    }

    @Test
    fun takeReturnsTheSavedDraftAndClearsIt() {
        ComposeDraftCache.save(draft(subject = "Hello"))

        assertEquals("Hello", ComposeDraftCache.take()?.subject)
        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun anEmptyDraftIsNotWorthKeeping() {
        ComposeDraftCache.save(draft())

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun aTypedFieldOtherThanSubjectIsWorthKeeping() {
        ComposeDraftCache.save(draft(bodyHtml = "<p>hi</p>"))

        assertEquals("<p>hi</p>", ComposeDraftCache.take()?.bodyHtml)
    }

    @Test
    fun anAttachmentAloneIsWorthKeeping() {
        ComposeDraftCache.save(
            draft(attachments = listOf(OutgoingAttachment("photo.jpg", "image/jpeg", "base64", 1024))),
        )

        assertEquals("photo.jpg", ComposeDraftCache.take()?.attachments?.single()?.name)
    }

    @Test
    fun clearSealsAgainstALateWrite() {
        ComposeDraftCache.clear()

        ComposeDraftCache.save(draft(subject = "Late Arrival"))

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun takeUnsealsForTheNextSession() {
        ComposeDraftCache.clear()
        ComposeDraftCache.take()

        ComposeDraftCache.save(draft(subject = "Grace Hopper"))

        assertEquals("Grace Hopper", ComposeDraftCache.take()?.subject)
    }

    @Test
    fun resetForNewSessionDropsEverything() {
        ComposeDraftCache.save(draft(subject = "Ada Lovelace"))

        ComposeDraftCache.resetForNewSession()

        assertNull(ComposeDraftCache.take())
    }

    private fun draft(
        to: String = "",
        cc: String = "",
        bcc: String = "",
        subject: String = "",
        bodyHtml: String = "",
        attachments: List<OutgoingAttachment> = emptyList(),
    ) = CachedDraft(to = to, cc = cc, bcc = bcc, subject = subject, bodyHtml = bodyHtml, attachments = attachments)
}
