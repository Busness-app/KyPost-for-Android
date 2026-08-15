package org.kysecurity.mail

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.mail.OutgoingAttachment

/**
 * Mirrors ContactEditDraftCacheTest's contract for the sibling cache: a draft survives Activity
 * destruction via save()/take(), take() hands ownership to the caller, clear() seals the cache
 * against a late write, and take() unseals for the next session. Plus the compose-specific rule
 * that an attachment alone — no text anywhere — is still worth keeping.
 */
class ComposeDraftCacheTest {

    /** clear() deliberately seals, and this cache is a process-wide object shared by every test in
     *  the JVM. A bare clear() would leak that seal into the next test and silently no-op its
     *  save(); take() drops the draft *and* unseals, which is the pristine state. */
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

    /** No recipients, no subject, no body — an attachment alone is still real work the user picked
     *  and would lose. "attachments included" is the spec's own phrase for this case. */
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
