package org.kysecurity.mail.contacts

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ContactEditDraftCacheTest {

    /** The cache is process-wide: clear() seals it, and only take() unseals for the next test. */
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

    @Test
    fun aDraftIsNeverHandedToADifferentContact() {
        ContactEditDraftCache.save(UID_A, ContactDto(uid = UID_A, fn = "Ada Lovelace"))

        assertNull(ContactEditDraftCache.take(UID_B))
    }

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
