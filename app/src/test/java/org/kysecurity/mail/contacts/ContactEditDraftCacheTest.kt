package org.kysecurity.mail.contacts

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Mirrors ComposeDraftCacheTest's contract: a draft survives Activity destruction, a take() hands
 * ownership to the caller, and a clear() seals the cache against a late write from the session
 * that was just wiped. Plus the contact-specific rule that a draft only ever goes back to the
 * contact it came from.
 */
class ContactEditDraftCacheTest {

    /** clear() deliberately seals, and this cache is a process-wide object shared by every test in
     *  the JVM. A bare clear() would leak that seal into the next test and silently no-op its
     *  save(); take() drops the draft *and* unseals, which is the pristine state. */
    @After
    fun tearDown() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take(ANY_UID)
    }

    @Test
    fun takeReturnsTheSavedDraftAndClearsIt() {
        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Ada Lovelace"))

        assertEquals("Ada Lovelace", ContactEditDraftCache.take(UID_A)?.fn)
        assertNull(ContactEditDraftCache.take(UID_A))
    }

    @Test
    fun anEmptyDraftIsNotWorthKeeping() {
        ContactEditDraftCache.save(UID_A, ContactDto())

        assertNull(ContactEditDraftCache.take(UID_A))
    }

    @Test
    fun aTypedFieldOtherThanTheNameIsWorthKeeping() {
        ContactEditDraftCache.save(
            "",
            ContactDto(phones = listOf(ContactFieldDto(value = "+1 555 0100"))),
        )

        assertEquals("+1 555 0100", ContactEditDraftCache.take("")?.phones?.single()?.value)
    }

    /**
     * The app lock finishes the editor and the unlock returns the user to the inbox, so contact A's
     * draft can outlive A's screen. It must not then be handed to contact B, whose save would
     * overwrite B with A's fields under B's uid.
     */
    @Test
    fun aDraftIsNeverHandedToADifferentContact() {
        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Ada Lovelace"))

        assertNull(ContactEditDraftCache.take(UID_B))
    }

    /** A mismatch drops the draft rather than leaving it to find a later victim. */
    @Test
    fun aMismatchedTakeDropsTheDraft() {
        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Ada Lovelace"))

        ContactEditDraftCache.take(UID_B)

        assertNull(ContactEditDraftCache.take(UID_A))
    }

    @Test
    fun clearSealsAgainstALateWrite() {
        ContactEditDraftCache.clear()

        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Late Arrival"))

        assertNull(ContactEditDraftCache.take(UID_A))
    }

    @Test
    fun takeUnsealsForTheNextSession() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take(UID_A)

        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Grace Hopper"))

        assertEquals("Grace Hopper", ContactEditDraftCache.take(UID_A)?.fn)
    }

    @Test
    fun resetForNewSessionDropsEverything() {
        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Ada Lovelace"))

        ContactEditDraftCache.resetForNewSession()

        assertNull(ContactEditDraftCache.take(UID_A))
    }

    private companion object {
        const val UID_A = "contact-a"
        const val UID_B = "contact-b"
        const val ANY_UID = ""
    }
}
