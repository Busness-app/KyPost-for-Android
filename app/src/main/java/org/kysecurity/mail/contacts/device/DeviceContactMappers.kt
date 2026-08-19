package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.contacts.toDto as toCanonicalDto

object DeviceContactMappers {
    fun ContactEntity.toDto(): ContactDto = toCanonicalDto()

    fun DeviceRawContactSnapshot.toContactDto(uid: String, rev: Long): ContactDto {
        return ContactDto(
            uid = uid,
            rev = rev,
            deleted = false,
            fn = fn,
            givenName = null,
            familyName = null,
            middleName = null,
            prefix = null,
            suffix = null,
            nickname = null,
            org = org,
            title = null,
            notes = notes,
            birthday = birthday,
            emails = emails,
            phones = phones,
            addresses = addresses,
            ims = ims,
            websites = websites,
            relations = relations,
            events = events,
            phoneticGivenName = phoneticGivenName,
            phoneticFamilyName = phoneticFamilyName,
            department = department,
        )
    }

    fun ContactDto.toDeviceFieldSet(): DeviceFieldSet {
        return DeviceFieldSet(
            fn = fn,
            givenName = givenName,
            familyName = familyName,
            middleName = middleName,
            prefix = prefix,
            suffix = suffix,
            nickname = nickname,
            org = org,
            title = title,
            notes = notes,
            birthday = birthday,
            emails = emails,
            phones = phones,
            addresses = addresses,
            groupIDs = groupIDs,
            ims = ims,
            websites = websites,
            relations = relations,
            events = events,
            phoneticGivenName = phoneticGivenName,
            phoneticFamilyName = phoneticFamilyName,
            department = department,
        )
    }
}
