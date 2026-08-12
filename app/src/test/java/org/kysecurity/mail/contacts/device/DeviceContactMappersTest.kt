package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactCustomFieldDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto
import org.kysecurity.mail.contacts.device.DeviceContactMappers.toContactDto
import org.kysecurity.mail.contacts.device.DeviceContactMappers.toDeviceFieldSet
import org.kysecurity.mail.contacts.device.DeviceContactMappers.toDto
import org.kysecurity.mail.contacts.toEntity
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [DeviceContactMappers.ContactEntity.toDto] is the merge base for both directions of device
 * sync ([DeviceContactRepository.pullDeviceChangesForOwnAccount]'s `roomDto.copy(...)` and
 * [DeviceContactRepository.pushRoomChangesToDevice]'s `entity.toDto()`). It used to be its own
 * partial re-implementation that silently dropped every Task-2-added field — this test guards
 * against that regression by asserting the fields this task's device provider wiring never
 * touches (`pgpKey`/`pronouns`/`customFields`/`groupIDs`/`photoRef`) still survive the
 * `ContactEntity -> ContactDto` conversion used on every device sync pass, per
 * `Client_Contact_Update.md`'s Part 5 checklist item.
 */
class DeviceContactMappersTest {

    private val fullDto = ContactDto(
        uid = "uid-1",
        rev = 5,
        fn = "Ada Lovelace",
        org = "Analytical Engines Ltd",
        notes = "Pioneer",
        birthday = "1815-12-10",
        groupIDs = listOf("group-1", "group-2"),
        photoRef = "abc123.jpg",
        pgpKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----",
        ims = listOf(ContactImDto(service = "signal", value = "+15551234567")),
        websites = listOf(ContactUrlDto(label = "homepage", value = "https://example.com")),
        relations = listOf(ContactRelationDto(label = "spouse", name = "William King")),
        events = listOf(ContactEventDto(label = "anniversary", date = "1835-07-08")),
        phoneticGivenName = "AH-duh",
        phoneticFamilyName = "LUV-lace",
        department = "Engineering",
        customFields = listOf(ContactCustomFieldDto(label = "Employee ID", value = "42")),
        pronouns = "she/her",
    )

    @Test
    fun toDto_roundTripsAppOnlyFieldsThatNeverTouchTheDeviceProvider() {
        val entity = fullDto.toEntity()

        val roundTripped = entity.toDto()

        assertEquals(fullDto.groupIDs, roundTripped.groupIDs)
        assertEquals(fullDto.photoRef, roundTripped.photoRef)
        assertEquals(fullDto.pgpKey, roundTripped.pgpKey)
        assertEquals(fullDto.customFields, roundTripped.customFields)
        assertEquals(fullDto.pronouns, roundTripped.pronouns)
    }

    @Test
    fun toDto_alsoRoundTripsTheNewlyDeviceWiredFields() {
        val entity = fullDto.toEntity()

        val roundTripped = entity.toDto()

        assertEquals(fullDto.ims, roundTripped.ims)
        assertEquals(fullDto.websites, roundTripped.websites)
        assertEquals(fullDto.relations, roundTripped.relations)
        assertEquals(fullDto.events, roundTripped.events)
        assertEquals(fullDto.phoneticGivenName, roundTripped.phoneticGivenName)
        assertEquals(fullDto.phoneticFamilyName, roundTripped.phoneticFamilyName)
        assertEquals(fullDto.department, roundTripped.department)
    }

    @Test
    fun toDeviceFieldSet_carriesGroupIdsAndTheNewFields() {
        val fieldSet = fullDto.toDeviceFieldSet()

        assertEquals(fullDto.groupIDs, fieldSet.groupIDs)
        assertEquals(fullDto.ims, fieldSet.ims)
        assertEquals(fullDto.websites, fieldSet.websites)
        assertEquals(fullDto.relations, fieldSet.relations)
        assertEquals(fullDto.events, fieldSet.events)
        assertEquals(fullDto.phoneticGivenName, fieldSet.phoneticGivenName)
        assertEquals(fullDto.phoneticFamilyName, fieldSet.phoneticFamilyName)
        assertEquals(fullDto.department, fieldSet.department)
    }

    @Test
    fun deviceRawContactSnapshot_toContactDto_carriesTheNewDeviceReadableFields() {
        val snapshot = DeviceRawContactSnapshot(
            rawContactId = 1L,
            contactId = 1L,
            accountType = "org.kysecurity.mail.contacts",
            accountName = null,
            lastUpdatedEpochMs = 1000L,
            dirty = false,
            fn = "Ada Lovelace",
            org = "Analytical Engines Ltd",
            notes = "Pioneer",
            birthday = "1815-12-10",
            emails = emptyList(),
            phones = emptyList(),
            addresses = emptyList(),
            ims = listOf(ContactImDto(service = "", label = "Signal", value = "+15551234567")),
            websites = listOf(ContactUrlDto(label = "homepage", value = "https://example.com")),
            relations = listOf(ContactRelationDto(label = "spouse", name = "William King")),
            events = listOf(ContactEventDto(label = "anniversary", date = "1835-07-08")),
            phoneticGivenName = "AH-duh",
            phoneticFamilyName = "LUV-lace",
            department = "Engineering",
        )

        val dto = snapshot.toContactDto("uid-1", 0)

        assertEquals(snapshot.ims, dto.ims)
        assertEquals(snapshot.websites, dto.websites)
        assertEquals(snapshot.relations, dto.relations)
        assertEquals(snapshot.events, dto.events)
        assertEquals(snapshot.phoneticGivenName, dto.phoneticGivenName)
        assertEquals(snapshot.phoneticFamilyName, dto.phoneticFamilyName)
        assertEquals(snapshot.department, dto.department)
        // Never sourced from the device -- must stay at their defaults for a freshly-imported contact.
        assertEquals(emptyList<String>(), dto.groupIDs)
        assertEquals(null, dto.pgpKey)
        assertEquals(emptyList<ContactCustomFieldDto>(), dto.customFields)
        assertEquals(null, dto.pronouns)
    }
}
