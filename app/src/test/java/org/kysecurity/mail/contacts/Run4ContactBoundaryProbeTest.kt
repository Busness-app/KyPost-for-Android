package org.kysecurity.mail.contacts

import org.kysecurity.mail.contacts.device.DeviceContactFieldMerge
import org.kysecurity.mail.contacts.device.DeviceContactMatcher
import org.kysecurity.mail.data.ContactEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SCRATCH / AUDIT PROBE — run-4 security audit, safe to delete.
 *
 * Reproduces the exact expressions used by
 * `DeviceContactRepository.pullDeviceChangesForOwnAccount` (the `changed` predicate at :252-259
 * and the `identityChanged` predicate at :283) over the real `DeviceContactFieldMerge` /
 * `DeviceContactMatcher` / `ContactMappers` production functions, so the boundary claims are
 * demonstrated rather than argued.
 */
class Run4ContactBoundaryProbeTest {

    // Room's contact was last written by the server an hour ago; the attacker's ContentProvider
    // write bumps CONTACT_LAST_UPDATED_TIMESTAMP to "now", which is what the device side reports.
    private val roomUpdatedAt = 1_000_000L
    private val deviceUpdatedAt = 2_000_000L

    // ---------------------------------------------------------------------------------------
    // A. identityChanged covers only `emails` and `fn`. Every other identity-bearing field can be
    //    rewritten by a WRITE_CONTACTS app, uploaded to the relay, and leave the trust badge green.
    // ---------------------------------------------------------------------------------------

    @Test
    fun devicePhoneRewrite_isUploaded_butDoesNotReArmReverification() {
        val roomPhones = listOf(ContactFieldDto(label = "mobile", value = "+1 555 0100"))
        val devicePhones = listOf(ContactFieldDto(label = "mobile", value = "+1 555 9999"))
        val roomEmails = listOf(ContactFieldDto(label = "work", value = "alice@corp.example"))

        val mergedPhones = DeviceContactFieldMerge.mergePhoneList(
            roomPhones = roomPhones,
            devicePhones = devicePhones,
            roomUpdatedAtEpochMs = roomUpdatedAt,
            deviceUpdatedAtEpochMs = deviceUpdatedAt,
        )
        val mergedEmails = DeviceContactFieldMerge.mergeEmailList(
            roomEmails = roomEmails,
            deviceEmails = roomEmails,
            roomUpdatedAtEpochMs = roomUpdatedAt,
            deviceUpdatedAtEpochMs = deviceUpdatedAt,
        )
        val mergedFn = DeviceContactFieldMerge.mergeStringField(
            roomValue = "Alice Smith",
            deviceValue = "Alice Smith",
            roomUpdatedAtEpochMs = roomUpdatedAt,
            deviceUpdatedAtEpochMs = deviceUpdatedAt,
        )

        // The device wins on the newer timestamp, so the attacker's number replaces the whole list.
        assertEquals(devicePhones, mergedPhones)

        // DeviceContactRepository.kt:252-259 — `changed` is true, so queueUpdate runs and the row
        // is pushed to the paired relay.
        val changed = mergedPhones != roomPhones
        assertTrue(changed)

        // DeviceContactRepository.kt:283 — but identityChanged is false, because it looks only at
        // emails and fn.
        val identityChanged = mergedEmails != roomEmails || mergedFn != "Alice Smith"
        assertFalse(identityChanged)

        // ...so the trust badge stays green on a contact whose phone number is now the attacker's.
        val previous = ContactEntity(
            uid = "uid-alice",
            rev = 4,
            fn = "Alice Smith",
            pgpKey = TEST_KEY,
            pgpKeyFingerprint = TEST_KEY_FINGERPRINT,
            pgpKeyNeedsReverification = false,
        )
        val poisoned = ContactDto(
            uid = "uid-alice",
            rev = 4,
            fn = "Alice Smith",
            emails = roomEmails,
            phones = mergedPhones,
            pgpKey = TEST_KEY,
        )
        val entity = poisoned.toEntity(previous, identityChanged = identityChanged)

        assertFalse("badge stays green after an attacker phone rewrite", entity.pgpKeyNeedsReverification)
        assertEquals(TEST_KEY, entity.pgpKey)
    }

    @Test
    fun deviceOrgNotesAddressImWebsiteRewrites_alsoDoNotReArmReverification() {
        // Every one of these is rendered on ContactDetailActivity beside the "key on file" badge
        // and every one of them is uploaded, yet none is part of identityChanged.
        val mergedOrg = DeviceContactFieldMerge.mergeStringField(
            "Corp Ltd", "Attacker Holdings", roomUpdatedAt, deviceUpdatedAt,
        )
        val mergedNotes = DeviceContactFieldMerge.mergeStringField(
            "met at conf", "New address: mallory@evil.example", roomUpdatedAt, deviceUpdatedAt,
        )
        val mergedWebsites = DeviceContactFieldMerge.mergeWebsiteList(
            roomWebsites = listOf(ContactUrlDto(value = "https://corp.example")),
            deviceWebsites = listOf(ContactUrlDto(value = "https://corp-secure-login.example")),
            roomUpdatedAtEpochMs = roomUpdatedAt,
            deviceUpdatedAtEpochMs = deviceUpdatedAt,
        )
        val mergedIms = DeviceContactFieldMerge.mergeImList(
            roomIms = listOf(ContactImDto(service = "signal", value = "+15550100")),
            deviceIms = listOf(ContactImDto(service = "signal", value = "+15559999")),
            roomUpdatedAtEpochMs = roomUpdatedAt,
            deviceUpdatedAtEpochMs = deviceUpdatedAt,
        )

        assertEquals("Attacker Holdings", mergedOrg)
        assertEquals("New address: mallory@evil.example", mergedNotes)
        assertEquals("https://corp-secure-login.example", mergedWebsites.single().value)
        assertEquals("+15559999", mergedIms.single().value)

        // identityChanged only consults emails and fn, neither of which moved.
        val identityChanged = false
        val previous = ContactEntity(
            uid = "uid-b", rev = 1, fn = "Bob",
            pgpKey = TEST_KEY, pgpKeyFingerprint = TEST_KEY_FINGERPRINT,
        )
        val entity = ContactDto(uid = "uid-b", rev = 1, fn = "Bob", pgpKey = TEST_KEY, org = mergedOrg)
            .toEntity(previous, identityChanged = identityChanged)
        assertFalse(entity.pgpKeyNeedsReverification)
    }

    @Test
    fun mergeEmailList_deviceSideWinsWholeListOnNewerTimestamp() {
        // Control: proves the timestamp the attacker controls decides the whole list, which is why
        // the identityChanged predicate has to be complete.
        val room = listOf(ContactFieldDto(value = "alice@corp.example"))
        val device = listOf(ContactFieldDto(value = "alice@corp-secure.example"))
        assertEquals(
            device,
            DeviceContactFieldMerge.mergeEmailList(room, device, roomUpdatedAt, deviceUpdatedAt),
        )
    }

    // ---------------------------------------------------------------------------------------
    // B. The QR ceremony clears a reverification alarm that was raised about ADDRESSES, having
    //    verified only the KEY. PgpKeyActivity.saveKeyToContact:333-340 builds the DTO from the
    //    (already tampered) Room row and passes verifiedInPerson = true.
    // ---------------------------------------------------------------------------------------

    @Test
    fun qrSaveToExistingContact_clearsAnAlarmRaisedAboutInjectedAddresses() {
        // State after a WRITE_CONTACTS app rewrote the address list: alarm armed.
        val tamperedEmails = listOf(
            ContactFieldDto(value = "alice@corp.example"),
            ContactFieldDto(value = "alice.smith@corp-secure.example"), // attacker-controlled
        )
        val tampered = ContactEntity(
            uid = "uid-alice",
            rev = 5,
            fn = "Alice Smith",
            emailsJson = """[{"value":"alice@corp.example"},{"value":"alice.smith@corp-secure.example"}]""",
            pgpKey = TEST_KEY,
            pgpKeyFingerprint = TEST_KEY_FINGERPRINT,
            pgpKeyNeedsReverification = true,
        )
        assertTrue(tampered.pgpKeyNeedsReverification)

        // PgpKeyActivity.saveKeyToContact: entity.toDto().copy(pgpKey = scannedKey).
        val dto = tampered.toDto().copy(pgpKey = TEST_KEY)
        assertEquals(tamperedEmails.map { it.value }, dto.emails.map { it.value })

        val afterCeremony = dto.toEntity(previous = tampered, verifiedInPerson = true)

        // The alarm is gone, and the attacker's address is now carried on a contact the app
        // considers verified in person, and is re-uploaded to the relay by the same call.
        assertFalse(afterCeremony.pgpKeyNeedsReverification)
        assertEquals(
            "alice.smith@corp-secure.example",
            afterCeremony.toDto().emails[1].value,
        )
    }

    // ---------------------------------------------------------------------------------------
    // C. DeviceContactMatcher.Index indexes empty normalized values, creating wildcard buckets.
    // ---------------------------------------------------------------------------------------

    @Test
    fun matcherIndex_digitFreePhoneDoesNotCreateAWildcardBucket() {
        // Regression: a single stored contact carrying a placeholder phone used to poison the whole
        // index, because normalizePhone strips every non-digit and "n/a" collapses to "". Every
        // later candidate whose phone had no digits then matched THAT contact and was silently
        // skipped by importNewDeviceContacts — so unrelated contacts were never imported.
        val existing = listOf(
            ContactDto(uid = "uid-placeholder", fn = "Front Desk", phones = listOf(ContactFieldDto(value = "n/a"))),
            ContactDto(uid = "uid-real", fn = "Alice", emails = listOf(ContactFieldDto(value = "alice@corp.example"))),
        )
        val index = DeviceContactMatcher.Index.of(existing)

        assertEquals("", DeviceContactMatcher.normalizePhone("n/a"))
        assertEquals("", DeviceContactMatcher.normalizePhone("-"))

        // A value that identifies nobody must match nobody.
        val matched = index.findMatch(
            candidateEmails = listOf("someone.else@other.example"),
            candidatePhones = listOf("-"),
        )
        assertNull(matched)

        // Real identifiers still match.
        assertEquals(
            "uid-real",
            index.findMatch(candidateEmails = listOf("alice@corp.example"), candidatePhones = emptyList()),
        )
    }

    @Test
    fun matcherIndex_emptyEmailValueDoesNotCreateAWildcardBucketEither() {
        // Server DTOs allow ContactFieldDto(value = "") — it is the default, so this arose without
        // any placeholder being typed by a user.
        val existing = listOf(ContactDto(uid = "uid-x", fn = "X", emails = listOf(ContactFieldDto(label = "work"))))
        val index = DeviceContactMatcher.Index.of(existing)
        assertNull(index.findMatch(candidateEmails = listOf("   "), candidatePhones = emptyList()))
    }

    // ---------------------------------------------------------------------------------------
    // D. Control: a device-side merge can never clear a stored key, so the ONLY way a
    //    WRITE_CONTACTS app can destroy a pinned key is the DELETE branch — which drops the Room
    //    row (key, fingerprint and alarm together) before any server round trip.
    // ---------------------------------------------------------------------------------------

    @Test
    fun mergeNeverClearsAStoredKey_soDeletionIsTheOnlyDestructivePath() {
        val room = ContactDto(uid = "u", fn = "Alice", pgpKey = TEST_KEY, emails = listOf(ContactFieldDto(value = "a@b.example")))
        // mergedDto = roomDto.copy(...) never touches pgpKey.
        val merged = room.copy(emails = listOf(ContactFieldDto(value = "evil@x.example")))
        assertEquals(TEST_KEY, merged.pgpKey)

        // Whereas ContactSyncRepository.queueDelete calls contactDao().deleteByUids first: the row
        // holding pgpKey / pgpKeyFingerprint / pgpKeyNeedsReverification simply ceases to exist,
        // so there is nothing left for toEntity's rotation or identity checks to compare against.
        val reImported = ContactDto(uid = "new-uid", fn = "Alice Smith", emails = listOf(ContactFieldDto(value = "a@b.example")))
            .toEntity(previous = null)
        assertNull(reImported.pgpKey)
        assertNull(reImported.pgpKeyFingerprint)
        assertFalse(reImported.pgpKeyNeedsReverification)
        assertNotNull(reImported.uid)
    }

    private companion object {
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
