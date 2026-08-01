package com.urlxl.mail.contacts

import com.urlxl.mail.data.ContactEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactMappersTest {

    @Test
    fun toEntity_toDto_roundTripsAllExtendedFields() {
        val dto = ContactDto(
            uid = "uid-1",
            rev = 1,
            fn = "Ada Lovelace",
            groupIDs = listOf("group-1", "group-2"),
            photoRef = "photo-ref-1",
            pgpKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----",
            ims = listOf(ContactImDto(service = "signal", label = "Home", value = "ada.lovelace")),
            websites = listOf(ContactUrlDto(label = "Blog", value = "https://example.com")),
            relations = listOf(ContactRelationDto(label = "Spouse", name = "William King")),
            events = listOf(ContactEventDto(label = "Anniversary", date = "1835-07-08")),
            phoneticGivenName = "AY-dah",
            phoneticFamilyName = "LUV-lace",
            department = "Analytical Engines",
            customFields = listOf(ContactCustomFieldDto(label = "Employee ID", value = "42")),
            pronouns = "she/her",
        )

        val entity = dto.toEntity()
        val roundTripped = entity.toDto()

        assertEquals(dto.groupIDs, roundTripped.groupIDs)
        assertEquals(dto.photoRef, roundTripped.photoRef)
        assertEquals(dto.pgpKey, roundTripped.pgpKey)
        assertEquals(dto.ims, roundTripped.ims)
        assertEquals(dto.websites, roundTripped.websites)
        assertEquals(dto.relations, roundTripped.relations)
        assertEquals(dto.events, roundTripped.events)
        assertEquals(dto.phoneticGivenName, roundTripped.phoneticGivenName)
        assertEquals(dto.phoneticFamilyName, roundTripped.phoneticFamilyName)
        assertEquals(dto.department, roundTripped.department)
        assertEquals(dto.customFields, roundTripped.customFields)
        assertEquals(dto.pronouns, roundTripped.pronouns)
    }

    @Test
    fun toEntity_defaultExtendedFields_encodeAsEmptyJsonArraysAndNulls() {
        val dto = ContactDto(uid = "uid-2", fn = "No Extras")

        val entity = dto.toEntity()

        assertEquals("[]", entity.groupIDsJson)
        assertEquals(null, entity.photoRef)
        assertEquals(null, entity.pgpKey)
        assertEquals("[]", entity.imsJson)
        assertEquals("[]", entity.websitesJson)
        assertEquals("[]", entity.relationsJson)
        assertEquals("[]", entity.eventsJson)
        assertEquals(null, entity.phoneticGivenName)
        assertEquals(null, entity.phoneticFamilyName)
        assertEquals(null, entity.department)
        assertEquals("[]", entity.customFieldsJson)
        assertEquals(null, entity.pronouns)
    }

    @Test
    fun toDto_blankJsonColumns_decodeAsEmptyLists() {
        val entity = ContactDto(uid = "uid-3", fn = "Legacy Row").toEntity().copy(
            groupIDsJson = "not json",
            imsJson = "not json",
            websitesJson = "not json",
            relationsJson = "not json",
            eventsJson = "not json",
            customFieldsJson = "not json",
        )

        val dto = entity.toDto()

        assertEquals(emptyList<String>(), dto.groupIDs)
        assertEquals(emptyList<ContactImDto>(), dto.ims)
        assertEquals(emptyList<ContactUrlDto>(), dto.websites)
        assertEquals(emptyList<ContactRelationDto>(), dto.relations)
        assertEquals(emptyList<ContactEventDto>(), dto.events)
        assertEquals(emptyList<ContactCustomFieldDto>(), dto.customFields)
    }

    @Test
    fun toEntity_toDto_roundTripsIsSelf() {
        val selfDto = ContactDto(uid = "uid-self", fn = "Me", isSelf = true)
        val otherDto = ContactDto(uid = "uid-other", fn = "Not Me", isSelf = false)

        assertEquals(true, selfDto.toEntity().toDto().isSelf)
        assertEquals(true, selfDto.toEntity().isSelf)
        assertEquals(false, otherDto.toEntity().toDto().isSelf)
        assertEquals(false, otherDto.toEntity().isSelf)
    }

    // ---- pgpKey fingerprint verification / rotation detection ----

    @Test
    fun toEntity_firstTimeKey_storesFingerprint_notFlaggedAsRotated() {
        val dto = ContactDto(uid = "uid-4", fn = "Fresh Contact", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous = null)

        assertEquals(TEST_KEY_FINGERPRINT, entity.pgpKeyFingerprint)
        assertFalse(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_keyUnchangedFromPrevious_notFlaggedAsRotated() {
        val previous = ContactEntity(uid = "uid-5", rev = 1, fn = "Stable Contact", pgpKeyFingerprint = TEST_KEY_FINGERPRINT)
        val dto = ContactDto(uid = "uid-5", rev = 2, fn = "Stable Contact", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous)

        assertEquals(TEST_KEY_FINGERPRINT, entity.pgpKeyFingerprint)
        assertFalse(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_keyRotatedFromPrevious_flaggedForReverification() {
        val previous = ContactEntity(uid = "uid-6", rev = 1, fn = "Rotated Contact", pgpKeyFingerprint = "AAAA BBBB")
        val dto = ContactDto(uid = "uid-6", rev = 2, fn = "Rotated Contact", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous)

        assertEquals(TEST_KEY_FINGERPRINT, entity.pgpKeyFingerprint)
        assertTrue(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_identityChangedOnKeyBearingContact_flaggedForReverification() {
        // A device-side edit carries the key over untouched, so the fingerprint is unchanged and
        // the rotation check cannot fire — but the key no longer vouches for the address it is
        // displayed beside. Any app holding WRITE_CONTACTS can drive this.
        val previous = ContactEntity(uid = "uid-8", rev = 1, fn = "Alice", pgpKeyFingerprint = TEST_KEY_FINGERPRINT)
        val dto = ContactDto(uid = "uid-8", rev = 2, fn = "Alice", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous, identityChanged = true)

        assertEquals(TEST_KEY_FINGERPRINT, entity.pgpKeyFingerprint)
        assertTrue(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_identityChangedOnContactWithNoKey_notFlagged() {
        // Nothing is vouching for anything, so there is no alarm to raise. Flagging here would
        // put a reverification badge on every ordinary contact edit.
        val previous = ContactEntity(uid = "uid-9", rev = 1, fn = "Bob")
        val dto = ContactDto(uid = "uid-9", rev = 2, fn = "Bob")

        val entity = dto.toEntity(previous, identityChanged = true)

        assertFalse(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_keyRotationVerifiedInPerson_isCleared() {
        // The QR ceremony attests to the KEY: the user compared this fingerprint against the other
        // person's device, so a rotation it confirms must clear rather than raise — otherwise the
        // app's only TOFU alarm fires on the one path where reverification is provably unnecessary,
        // and users learn to dismiss it.
        val previous = ContactEntity(uid = "uid-10", rev = 1, fn = "Carol", pgpKeyFingerprint = "AAAA BBBB")
        val dto = ContactDto(uid = "uid-10", rev = 2, fn = "Carol", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous, verifiedInPerson = true, identityChanged = false)

        assertFalse(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_identityReboundSurvivesVerifiedInPerson() {
        // ...but it attests to nothing about WHICH ADDRESSES that key is bound to. The QR save path
        // builds its DTO from the current Room row, while the confirmation screen shows the
        // addresses from the scanned card — so a WRITE_CONTACTS app could inject an address, and the
        // user's own recommended remediation (scan the key again) would clear the alarm that
        // injection raised. A rebind is a different claim from a rotation and outlives the ceremony.
        val previous = ContactEntity(uid = "uid-11", rev = 1, fn = "Carol", pgpKeyFingerprint = TEST_KEY_FINGERPRINT)
        val dto = ContactDto(uid = "uid-11", rev = 2, fn = "Carol", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous, verifiedInPerson = true, identityChanged = true)

        assertTrue(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_reverificationFlagStaysSetUntilKeyStabilizes() {
        val previous = ContactEntity(
            uid = "uid-7",
            rev = 1,
            fn = "Still Unverified",
            pgpKeyFingerprint = TEST_KEY_FINGERPRINT,
            pgpKeyNeedsReverification = true,
        )
        val dto = ContactDto(uid = "uid-7", rev = 2, fn = "Still Unverified", pgpKey = TEST_KEY)

        val entity = dto.toEntity(previous)

        // Same key as last sync (already flagged) — stays flagged until the user re-verifies;
        // an unrelated sync of the same key must not silently clear the warning.
        assertTrue(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun toEntity_unparseableKey_storesNoFingerprint() {
        val dto = ContactDto(uid = "uid-8", fn = "Bad Key", pgpKey = "not a real pgp key")

        val entity = dto.toEntity(previous = null)

        assertNull(entity.pgpKeyFingerprint)
        assertFalse(entity.pgpKeyNeedsReverification)
    }

    private companion object {
        // Same disposable test fixture as PgpFingerprintTest — a throwaway ed25519 key generated
        // with `gpg --quick-generate-key`, with gpg's own reported fingerprint alongside it.
        const val TEST_KEY_FINGERPRINT = "164D 5B83 4E7F E927 2DC7 293B 6D78 ABF3 D917 9534"
        val TEST_KEY = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----

            mDMEalxKSBYJKwYBBAHaRw8BAQdAaLBvayt/AqeBFCxDOrvjb36gwol5tI+JU+6p
            vOR9sTO0KVBncEZpbmdlcnByaW50VGVzdCA8dGVzdEBleGFtcGxlLmludmFsaWQ+
            iJAEExYKADgWIQQWTVuDTn/pJy3HKTtteKvz2ReVNAUCalxKSAIbAwULCQgHAgYV
            CgkICwIEFgIDAQIeAQIXgAAKCRBteKvz2ReVNAUoAQCi9uhyZCB8aY/iupXHv0j9
            3HOkEbVmB1B/xRn+xdcu4gEAn2JbiIts/RVYYk8RXwTVp3zrksdrTZ1zBiBUC/ZH
            TQ8=
            =+uqe
            -----END PGP PUBLIC KEY BLOCK-----
        """.trimIndent()
    }
}
