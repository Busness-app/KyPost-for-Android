package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.pgp.PgpFingerprint
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val mapperJson = Json { ignoreUnknownKeys = true }

/**
 * [previous] is the contact's existing row, if any, fetched by the caller before this sync
 * delta is applied. `pgpKey` arrives via ordinary two-way contact sync — unlike the QR
 * key-exchange flow, which independently recomputes and requires user confirmation of a
 * fingerprint before ever trusting a key — so this is the one place that same discipline is
 * applied to sync-derived keys: the fingerprint is (re)computed locally from the key bytes, and
 * a previously-verified fingerprint changing out from under the contact sets
 * [ContactEntity.pgpKeyNeedsReverification] instead of silently updating the trust badge.
 *
 * [verifiedInPerson] is set only by the QR key-exchange flow, where the user has just compared
 * this exact fingerprint out-of-band against the other person's device. That is the strongest
 * trust state the app can reach, so it must CLEAR the badge rather than raise it. Raising it
 * there — which is what happened when a contact legitimately rotated their key and the user
 * re-verified in person — trained users to dismiss the app's only TOFU alarm, and the badge is
 * plain text with no provenance, so a dismissed real key swap looks identical.
 */
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
    // [PgpFingerprint.compute] returns null for the shapes it refuses to vouch for — an appended
    // second key ring, a subkey bound by a foreign signature or by none — and its KDoc requires
    // callers to treat that as "reject this key". Reading it as "no information" meant a key the
    // local parser rejects raised nothing, which is the one alarm here that does not depend on the
    // relay's own verdict. It also cleared an outstanding alarm, because stillNeedsReverification
    // asks for newFingerprint == previousFingerprint and a null fingerprint never matches.
    val keyUnparseable = !verifiedInPerson && !pgpKey.isNullOrBlank() && newFingerprint == null
    // The mirror of [keyRotated]: same person, different key vs. same key, different person. A
    // device-side merge carries pgpKey over untouched, so the fingerprint is unchanged and the
    // rotation check cannot fire — but ContactsContract has no per-account write ACL, so any app
    // holding WRITE_CONTACTS can swap the address the key is displayed beside, and that edit is
    // then uploaded to the paired server. Re-arm on the identity, not just on the key.
    //
    // Deliberately NOT suppressed by verifiedInPerson, unlike the two above. A QR ceremony attests
    // to the *key*: the user compared a fingerprint. It says nothing about which addresses that key
    // is bound to, and the save path builds its DTO from the current — possibly already tampered —
    // Room row while the confirmation screen shows the addresses from the *scanned card*. So the
    // ceremony was clearing an alarm raised about an address injection it never examined, and doing
    // it as the user's own recommended remediation. A rotated key it does answer for; a rebound
    // identity it does not.
    // Raised by this sync, OR still outstanding from an earlier one. Carrying the previous value
    // forward is the half that was missing: identityRebound reflected only the CURRENT call, so a QR
    // ceremony (which passes identityChanged = false) dropped an alarm raised by an earlier sync.
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
        // The IDENTITY alarm, in its own column so the ceremony cannot clear it. A fingerprint
        // comparison attests to the key; it says nothing about which addresses that key is displayed
        // beside, and the save path builds its DTO from the current — possibly already tampered —
        // Room row while the confirmation screen shows the scanned card's addresses.
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
