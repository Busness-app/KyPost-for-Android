package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto

/**
 * `groupIDs` deliberately has no field here — group membership only ever flows Room -> device
 * (see [DeviceGroupLinker]), never read back from `GroupMembership` rows into Room, per
 * `Client_Contact_Update.md` Part 2 point 3. `pgpKey`/`pronouns`/`customFields` are excluded too:
 * they have no `ContactsContract` data kind at all (Part 5) and stay Room-only.
 */
data class DeviceRawContactSnapshot(
    val rawContactId: Long,
    val contactId: Long,
    val accountType: String?,
    val accountName: String?,
    val lastUpdatedEpochMs: Long,
    val dirty: Boolean,
    val fn: String,
    val org: String?,
    val notes: String?,
    val birthday: String?,
    val emails: List<ContactFieldDto>,
    val phones: List<ContactFieldDto>,
    val addresses: List<ContactAddressDto>,
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
)

data class DeviceContactCandidate(
    val contactId: Long,
    val rawContactId: Long,
    val lastUpdatedEpochMs: Long,
    val emails: List<String>,
    val phones: List<String>,
    val fn: String,
    val org: String?,
    val notes: String?,
)

/**
 * The write-intention shape ([org.kysecurity.mail.contacts.device.DeviceContactMappers.toDeviceFieldSet]
 * converts a [org.kysecurity.mail.contacts.ContactDto] into this). Unlike [DeviceRawContactSnapshot],
 * this *does* carry [groupIDs] — group membership is write-only (Room -> device), so it belongs on
 * the write side, not the read side. `pgpKey`/`pronouns`/`customFields` are still excluded (Part 5).
 */
data class DeviceFieldSet(
    val fn: String,
    val givenName: String?,
    val familyName: String?,
    val middleName: String?,
    val prefix: String?,
    val suffix: String?,
    val nickname: String?,
    val org: String?,
    val title: String?,
    val notes: String?,
    val birthday: String?,
    val emails: List<ContactFieldDto>,
    val phones: List<ContactFieldDto>,
    val addresses: List<ContactAddressDto>,
    val groupIDs: List<String> = emptyList(),
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
)
