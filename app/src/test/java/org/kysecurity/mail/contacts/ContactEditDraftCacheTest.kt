package org.kysecurity.mail.contacts

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Mirrors ComposeDraftCacheTest's contract: a draft survives Activity destruction, a take() hands
 * ownership to the caller, and a clear() seals the cache against a late write from the session
 * that was just wiped.
 */
class ContactEditDraftCacheTest {

    /** clear() deliberately seals, and this cache is a process-wide object shared by every test in
     *  the JVM. A bare clear() would leak that seal into the next test and silently no-op its
     *  save(); take() drops the draft *and* unseals, which is the pristine state. */
    @After
    fun tearDown() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take()
    }

    @Test
    fun takeReturnsTheSavedDraftAndClearsIt() {
        ContactEditDraftCache.save(ContactDto(fn = "Ada Lovelace"))

        assertEquals("Ada Lovelace", ContactEditDraftCache.take()?.fn)
        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun anEmptyDraftIsNotWorthKeeping() {
        ContactEditDraftCache.save(ContactDto())

        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun clearSealsAgainstALateWrite() {
        ContactEditDraftCache.clear()

        ContactEditDraftCache.save(ContactDto(fn = "Late Arrival"))

        assertNull(ContactEditDraftCache.take())
    }

    @Test
    fun takeUnsealsForTheNextSession() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take()

        ContactEditDraftCache.save(ContactDto(fn = "Grace Hopper"))

        assertEquals("Grace Hopper", ContactEditDraftCache.take()?.fn)
    }

    @Test
    fun resetForNewSessionDropsEverything() {
        ContactEditDraftCache.save(ContactDto(fn = "Ada Lovelace"))

        ContactEditDraftCache.resetForNewSession()

        assertNull(ContactEditDraftCache.take())
    }
}
