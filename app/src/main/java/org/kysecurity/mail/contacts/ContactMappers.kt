package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.pgp.PgpFingerprint
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val mapperJson = Json { ignoreUnknownKeys = true }

// Fingerprints are recomputed locally; an in-person QR check CLEARS the alarm, never raises it.
fun ContactDto.toEntity(
    previous: ContactEntity? = null,
    verifiedInPerson: Boolean = false,
    identityChanged: Boolean = false,
): ContactEntity {
    val newFingerprint = pgpKey?.let { PgpFingerprint.compute(it) }
    val previousFingerprint = previous?.pgpKeyFingerprint
    val keyRotated = !verifiedInPerson &&
        previousFingerprint != null && newFingerprint != null && previousFingerprint != newFingerprint
    val stillNeedsReverification = !verifiedInPerson &&
        previous?.pgpKeyNeedsReverification == true && newFingerprint == previousFingerprint
    // A null from [PgpFingerprint.compute] means "reject this key", not "no information".
    val keyUnparseable = !verifiedInPerson && !pgpKey.isNullOrBlank() && newFingerprint == null
    // The mirror of keyRotated: same key, different person — a merge leaves the fingerprint intact.
    val identityRebound = (identityChanged || previous?.identityNeedsReview == true) &&
        !pgpKey.isNullOrBlank()

    return ContactEntity(
        uid = uid,
        rev = rev,
        createdAt = createdAt,
        updatedAt = updatedAt,
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
        emailsJson = mapperJson.encodeToString(emails),
        phonesJson = mapperJson.encodeToString(phones),
        addressesJson = mapperJson.encodeToString(addresses),
        groupIDsJson = mapperJson.encodeToString(groupIDs),
        photoRef = photoRef,
        pgpKey = pgpKey,
        imsJson = mapperJson.encodeToString(ims),
        websitesJson = mapperJson.encodeToString(websites),
        relationsJson = mapperJson.encodeToString(relations),
        eventsJson = mapperJson.encodeToString(events),
        phoneticGivenName = phoneticGivenName,
        phoneticFamilyName = phoneticFamilyName,
        department = department,
        customFieldsJson = mapperJson.encodeToString(customFields),
        pronouns = pronouns,
        isSelf = isSelf,
        pgpKeyFingerprint = newFingerprint ?: previousFingerprint,
        // The KEY alarm only. A QR fingerprint comparison answers this one, so verifiedInPerson
        // clearing it is correct.
        pgpKeyNeedsReverification = keyRotated || keyUnparseable || stillNeedsReverification,
        // The IDENTITY alarm, in its own column so the QR ceremony cannot clear it.
        identityNeedsReview = identityRebound,
    )
}

fun ContactEntity.toDto(): ContactDto = ContactDto(
    uid = uid,
    rev = rev,
    createdAt = createdAt,
    updatedAt = updatedAt,
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
    emails = runCatching { mapperJson.decodeFromString<List<ContactFieldDto>>(emailsJson) }.getOrDefault(emptyList()),
    phones = runCatching { mapperJson.decodeFromString<List<ContactFieldDto>>(phonesJson) }.getOrDefault(emptyList()),
    addresses = runCatching { mapperJson.decodeFromString<List<ContactAddressDto>>(addressesJson) }.getOrDefault(emptyList()),
    groupIDs = runCatching { mapperJson.decodeFromString<List<String>>(groupIDsJson) }.getOrDefault(emptyList()),
    photoRef = photoRef,
    pgpKey = pgpKey,
    ims = runCatching { mapperJson.decodeFromString<List<ContactImDto>>(imsJson) }.getOrDefault(emptyList()),
    websites = runCatching { mapperJson.decodeFromString<List<ContactUrlDto>>(websitesJson) }.getOrDefault(emptyList()),
    relations = runCatching { mapperJson.decodeFromString<List<ContactRelationDto>>(relationsJson) }.getOrDefault(emptyList()),
    events = runCatching { mapperJson.decodeFromString<List<ContactEventDto>>(eventsJson) }.getOrDefault(emptyList()),
    phoneticGivenName = phoneticGivenName,
    phoneticFamilyName = phoneticFamilyName,
    department = department,
    customFields = runCatching { mapperJson.decodeFromString<List<ContactCustomFieldDto>>(customFieldsJson) }.getOrDefault(emptyList()),
    pronouns = pronouns,
    isSelf = isSelf,
)
