package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Covers [mergedContactDto] — the pure piece pulled out of [ContactEditActivity.save] (mirrors
 * [ContactSyncRepositoryTest]'s extraction approach for the same reason: unit-testable without a
 * Context-backed Room/Activity). Regression test for a real data-loss bug: `save()` used to build a
 * brand-new [ContactDto] from only the fields this single-screen editor exposes, so saving any edit
 * (even just fixing a phone number) silently wiped every other field — locally immediately, and on
 * the server too, since both the local upsert and the server's PUT/push handlers fully replace the
 * stored contact rather than merging. [mergedContactDto] must `.copy()` off the loaded contact
 * instead.
 */
class ContactEditActivityTest {

    private val loaded = ContactDto(
        uid = "uid-1",
        rev = 5,
        fn = "Old Name",
        givenName = "Old",
        familyName = "Name",
        middleName = "Middle",
        prefix = "Dr.",
        suffix = "Jr.",
        nickname = "Nick",
        org = "Old Org",
        title = "Old Title",
        notes = "Old notes",
        birthday = "1990-01-01",
        emails = listOf(ContactFieldDto(value = "old@example.com")),
        phones = listOf(ContactFieldDto(value = "555-0000")),
        addresses = listOf(ContactAddressDto(city = "Springfield")),
        groupIDs = listOf("group-1"),
        photoRef = "photo-ref-1",
        pgpKey = "pgp-key-1",
        ims = listOf(ContactImDto(service = "signal", value = "old-im")),
        websites = listOf(ContactUrlDto(value = "https://old.example.com")),
        relations = listOf(ContactRelationDto(name = "Spouse")),
        events = listOf(ContactEventDto(date = "2020-01-01")),
        phoneticGivenName = "Oh-ld",
        phoneticFamilyName = "Nay-m",
        department = "Engineering",
        customFields = listOf(ContactCustomFieldDto(label = "Custom", value = "Value")),
        pronouns = "they/them",
        isSelf = true,
    )

    @Test
    fun mergedContactDto_editableFields_reflectEdits() {
        val result = mergedContactDto(
            loaded = loaded,
            uid = loaded.uid,
            rev = loaded.rev,
            fn = "New Name",
            givenName = "New",
            familyName = "Surname",
            middleName = "Mid",
            prefix = "Mx.",
            suffix = "III",
            nickname = "Newy",
            org = "New Org",
            title = "New Title",
            department = "Sales",
            notes = "New notes",
            birthday = "1991-02-02",
            emails = listOf(ContactFieldDto(value = "new@example.com")),
            phones = listOf(ContactFieldDto(value = "555-1111")),
            addresses = listOf(ContactAddressDto(city = "Shelbyville")),
            ims = listOf(ContactImDto(service = "telegram", value = "new-im")),
            websites = listOf(ContactUrlDto(value = "https://new.example.com")),
            relations = listOf(ContactRelationDto(name = "Sibling")),
            events = listOf(ContactEventDto(date = "2021-03-03")),
            phoneticGivenName = "New-uh",
            phoneticFamilyName = "Sur-name",
            customFields = listOf(ContactCustomFieldDto(label = "New Custom", value = "New Value")),
            pronouns = "she/her",
        )

        assertEquals("New Name", result.fn)
        assertEquals("New", result.givenName)
        assertEquals("Surname", result.familyName)
        assertEquals("Mid", result.middleName)
        assertEquals("Mx.", result.prefix)
        assertEquals("III", result.suffix)
        assertEquals("Newy", result.nickname)
        assertEquals("New Org", result.org)
        assertEquals("New Title", result.title)
        assertEquals("Sales", result.department)
        assertEquals("New notes", result.notes)
        assertEquals("1991-02-02", result.birthday)
        assertEquals(listOf(ContactFieldDto(value = "new@example.com")), result.emails)
        assertEquals(listOf(ContactFieldDto(value = "555-1111")), result.phones)
        assertEquals(listOf(ContactAddressDto(city = "Shelbyville")), result.addresses)
        assertEquals(listOf(ContactImDto(service = "telegram", value = "new-im")), result.ims)
        assertEquals(listOf(ContactUrlDto(value = "https://new.example.com")), result.websites)
        assertEquals(listOf(ContactRelationDto(name = "Sibling")), result.relations)
        assertEquals(listOf(ContactEventDto(date = "2021-03-03")), result.events)
        assertEquals("New-uh", result.phoneticGivenName)
        assertEquals("Sur-name", result.phoneticFamilyName)
        assertEquals(listOf(ContactCustomFieldDto(label = "New Custom", value = "New Value")), result.customFields)
        assertEquals("she/her", result.pronouns)
    }

    @Test
    fun mergedContactDto_deferredAndReadOnlyFields_alwaysSurviveUntouched() {
        val result = mergedContactDto(
            loaded = loaded,
            uid = loaded.uid,
            rev = loaded.rev,
            fn = "New Name",
            givenName = null,
            familyName = null,
            middleName = null,
            prefix = null,
            suffix = null,
            nickname = null,
            org = null,
            title = null,
            department = null,
            notes = null,
            birthday = null,
            emails = emptyList(),
            phones = emptyList(),
            addresses = emptyList(),
            ims = emptyList(),
            websites = emptyList(),
            relations = emptyList(),
            events = emptyList(),
            phoneticGivenName = null,
            phoneticFamilyName = null,
            customFields = emptyList(),
            pronouns = null,
        )

        // Never editable in ContactEditActivity — must survive regardless of what else changed.
        assertEquals(loaded.groupIDs, result.groupIDs)
        assertEquals(loaded.photoRef, result.photoRef)
        assertEquals(loaded.pgpKey, result.pgpKey)
        assertEquals(loaded.isSelf, result.isSelf)
    }

    @Test
    fun mergedContactDto_newContact_leavesUnsetFieldsAtDefaults() {
        val result = mergedContactDto(
            loaded = ContactDto(),
            uid = "",
            rev = 0,
            fn = "Brand New",
            givenName = null,
            familyName = null,
            middleName = null,
            prefix = null,
            suffix = null,
            nickname = null,
            org = null,
            title = null,
            department = null,
            notes = null,
            birthday = null,
            emails = emptyList(),
            phones = emptyList(),
            addresses = emptyList(),
            ims = emptyList(),
            websites = emptyList(),
            relations = emptyList(),
            events = emptyList(),
            phoneticGivenName = null,
            phoneticFamilyName = null,
            customFields = emptyList(),
            pronouns = null,
        )

        assertEquals(ContactDto(fn = "Brand New"), result)
    }
}
