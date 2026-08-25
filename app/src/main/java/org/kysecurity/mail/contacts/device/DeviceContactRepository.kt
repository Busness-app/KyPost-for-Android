package org.kysecurity.mail.contacts.device

import android.content.Context
import android.provider.ContactsContract
import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.ContactUrlDto
import org.kysecurity.mail.contacts.GroupSyncRepository
import org.kysecurity.mail.contacts.device.DeviceContactMappers.toContactDto
import org.kysecurity.mail.contacts.device.DeviceContactMappers.toDto
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID

class DeviceContactRepository(
    private val context: Context,
    private val db: AppDatabase,
    private val syncRepository: ContactSyncRepository,
    private val groupSyncRepository: GroupSyncRepository,
) {
    private val contentResolver = context.contentResolver
    private val groupLinker = DeviceGroupLinker(context, db)
    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    /** Re-read rather than captured, so a long-running sync notices protection being switched on
     *  mid-flight. The coordinator and the worker both gate on entry; this is the in-loop check. */
    private fun syncPermitted(): Boolean = !hostileLocationSettings.isEnabled()

    // CancellationException is an Exception, so it is rethrown: a cancelled sync must not run on.
    private suspend fun stage(name: String, body: suspend () -> Unit): String? =
        try {
            body()
            null
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            android.util.Log.e("DeviceContactSync", "Sync stage failed: $name", e)
            name
        }

    // Shares syncRepository.syncMutex with ContactSyncRepository.sync(); both write the same table.
    suspend fun syncAll(): List<String> = syncRepository.syncMutex.withLock {
        listOfNotNull(
            stage("ensureAccountVisible") { ensureAccountContactsVisible() },
            stage("pruneForeignLinks") { pruneForeignLinks() },
            stage("refreshGroups") {
                groupSyncRepository.sync()
                reconcileGroupRenames()
            },
            stage("pullDeviceChanges") { pullDeviceChangesForOwnAccount() },
            stage("importNewDeviceContacts") { importNewDeviceContacts() },
            stage("pushRoomChanges") { pushRoomChangesToDevice() },
        )
    }

    /** Runs every sync, not just at enable time, so installs that predate the fix repair themselves. */
    private suspend fun ensureAccountContactsVisible() = withContext(Dispatchers.IO) {
        DeviceContactAccount.makeContactsVisible(context)
    }

    /** Renames every already-linked group, not only those a brand-new contact references. */
    private suspend fun reconcileGroupRenames() = withContext(Dispatchers.IO) {
        val links = db.groupLinkDao().getAll()
        if (links.isEmpty()) return@withContext
        val groups = db.groupDao().getAll()
        for ((androidGroupRowId, freshName) in groupRenameTargets(links, groups)) {
            groupLinker.renameIfNeeded(androidGroupRowId, freshName)
        }
    }

    private suspend fun pullDeviceChangesForOwnAccount() = withContext(Dispatchers.IO) {
        val projection = arrayOf(
            ContactsContract.RawContacts._ID,
            ContactsContract.RawContacts.CONTACT_ID,
            ContactsContract.RawContacts.DELETED,
            // DIRTY has to be read, not assumed: a no-op UPDATE wakes our own observer into a loop.
            ContactsContract.RawContacts.DIRTY,
        )

        val selection = "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?"
        val selectionArgs = arrayOf(DeviceContactAccount.ACCOUNT_TYPE)

        val dirtyRawContacts = mutableListOf<Long>()

        // Loaded once; this used to be a Room query per row from inside the cursor loop.
        val linksByRawContactId = db.deviceContactLinkDao().getAll().associateBy { it.rawContactId }

        contentResolver.query(
            ContactsContract.RawContacts.CONTENT_URI,
            projection,
            selection,
            selectionArgs,
            null,
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val rawContactId = cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts._ID))
                val deleted = cursor.getInt(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts.DELETED)) != 0
                val dirty = cursor.getInt(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts.DIRTY)) != 0

                val link = linksByRawContactId[rawContactId]

                if (deleted && link != null) {
                    // A device-side delete is a PROPOSAL: any app can set DELETED=1 on our rows,
                    // so a contact holding a key is restored rather than tombstoned.
                    val existing = db.contactDao().getByUid(link.uid)
                    if (existing?.isSelf == true || !existing?.pgpKey.isNullOrBlank()) {
                        restoreDeletedRawContact(rawContactId)
                    } else {
                        syncRepository.queueDelete(link.uid, 0)
                        db.deviceContactLinkDao().deleteByUid(link.uid)
                    }
                } else if (!deleted && dirty && link != null) {
                    dirtyRawContacts.add(rawContactId)
                }
            }
        }

        // Same reasoning as linksByRawContactId above: one read of the contacts table instead of a
        // getByUid per dirty row.
        val roomByUid = db.contactDao().observeAll().first().associateBy { it.uid }

        for (rawContactId in dirtyRawContacts) {
            val snapshot = readRawContactSnapshot(rawContactId) ?: continue
            val link = linksByRawContactId[rawContactId] ?: continue

            val roomEntity = roomByUid[link.uid] ?: continue
            val roomDto = roomEntity.toDto()

            val roomUpdatedAtEpochMs = roomDto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) }
            val deviceUpdatedAtEpochMs = snapshot.lastUpdatedEpochMs

            val mergedFn = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.fn,
                deviceValue = snapshot.fn,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedOrg = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.org,
                deviceValue = snapshot.org,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedNotes = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.notes,
                deviceValue = snapshot.notes,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedBirthday = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.birthday,
                deviceValue = snapshot.birthday,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedEmails = DeviceContactFieldMerge.mergeEmailList(
                roomEmails = roomDto.emails,
                deviceEmails = snapshot.emails,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedPhones = DeviceContactFieldMerge.mergePhoneList(
                roomPhones = roomDto.phones,
                devicePhones = snapshot.phones,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedAddresses = DeviceContactFieldMerge.mergeAddressList(
                roomAddresses = roomDto.addresses,
                deviceAddresses = snapshot.addresses,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedIms = DeviceContactFieldMerge.mergeImList(
                roomIms = roomDto.ims,
                deviceIms = snapshot.ims,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedWebsites = DeviceContactFieldMerge.mergeWebsiteList(
                roomWebsites = roomDto.websites,
                deviceWebsites = snapshot.websites,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedRelations = DeviceContactFieldMerge.mergeRelationList(
                roomRelations = roomDto.relations,
                deviceRelations = snapshot.relations,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedEvents = DeviceContactFieldMerge.mergeEventList(
                roomEvents = roomDto.events,
                deviceEvents = snapshot.events,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedDepartment = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.department,
                deviceValue = snapshot.department,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedPhoneticGivenName = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.phoneticGivenName,
                deviceValue = snapshot.phoneticGivenName,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val mergedPhoneticFamilyName = DeviceContactFieldMerge.mergeStringField(
                roomValue = roomDto.phoneticFamilyName,
                deviceValue = snapshot.phoneticFamilyName,
                roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
            )

            val changed = mergedFn != roomDto.fn || mergedOrg != roomDto.org ||
                mergedNotes != roomDto.notes || mergedBirthday != roomDto.birthday ||
                mergedEmails != roomDto.emails || mergedPhones != roomDto.phones ||
                mergedAddresses != roomDto.addresses || mergedIms != roomDto.ims ||
                mergedWebsites != roomDto.websites || mergedRelations != roomDto.relations ||
                mergedEvents != roomDto.events || mergedDepartment != roomDto.department ||
                mergedPhoneticGivenName != roomDto.phoneticGivenName ||
                mergedPhoneticFamilyName != roomDto.phoneticFamilyName

            if (changed) {
                val mergedDto = roomDto.copy(
                    fn = mergedFn ?: "",
                    org = mergedOrg,
                    notes = mergedNotes,
                    birthday = mergedBirthday,
                    emails = mergedEmails,
                    phones = mergedPhones,
                    addresses = mergedAddresses,
                    ims = mergedIms,
                    websites = mergedWebsites,
                    relations = mergedRelations,
                    events = mergedEvents,
                    department = mergedDepartment,
                    phoneticGivenName = mergedPhoneticGivenName,
                    phoneticFamilyName = mergedPhoneticFamilyName,
                )
                // Any device-side change to a keyed contact changes who that key is displayed
                // beside, and the carried-over key hides it from toEntity's rotation check.
                syncRepository.queueUpdate(mergedDto, identityChanged = changed)
            }

            clearDirtyFlag(rawContactId)
            db.deviceContactLinkDao().upsert(
                link.copy(deviceUpdatedAtEpochMs = System.currentTimeMillis()),
            )
        }
    }

    private fun isSystemContact(snapshot: DeviceRawContactSnapshot): Boolean {
        val name = snapshot.fn.lowercase()
        return (name.contains("customer care") || name.contains("customer service") ||
            name.contains("411") || name.contains("611") ||
            name.contains("voicemail") || name.contains("support") ||
            name.contains("carrier") || name.contains("emergency") ||
            name.startsWith("*") || name.startsWith("#"))
    }

    /** Undoes a device-side delete of a row we refuse to tombstone. */
    private suspend fun restoreDeletedRawContact(rawContactId: Long) = withContext(Dispatchers.IO) {
        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        val ops = arrayListOf(
            android.content.ContentProviderOperation.newUpdate(uri)
                .withSelection("${ContactsContract.RawContacts._ID} = ?", arrayOf(rawContactId.toString()))
                .withValue(ContactsContract.RawContacts.DELETED, 0)
                .withValue(ContactsContract.RawContacts.DIRTY, 0)
                .withValue(
                    ContactsContract.RawContacts.AGGREGATION_MODE,
                    ContactsContract.RawContacts.AGGREGATION_MODE_DEFAULT,
                )
                .build(),
        )
        runCatching { contentResolver.applyBatch(ContactsContract.AUTHORITY, ops) }
            .onFailure {
                android.util.Log.e("DeviceContactSync", "Could not restore raw contact $rawContactId", it)
            }
        Unit
    }

    private suspend fun clearDirtyFlag(rawContactId: Long) = withContext(Dispatchers.IO) {
        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        val ops = arrayListOf(
            android.content.ContentProviderOperation.newUpdate(uri)
                .withSelection("${ContactsContract.RawContacts._ID} = ?", arrayOf(rawContactId.toString()))
                .withValue(ContactsContract.RawContacts.DIRTY, 0)
                .build(),
        )
        runCatching {
            contentResolver.applyBatch(ContactsContract.AUTHORITY, ops)
        }
    }

    private suspend fun importNewDeviceContacts() = withContext(Dispatchers.IO) {
        val settings = DeviceContactSyncSettings(context)
        val watermarkMs = settings.lastForeignScanAtEpochMs()

        val projection = arrayOf(
            ContactsContract.RawContacts._ID,
            ContactsContract.RawContacts.CONTACT_ID,
            ContactsContract.RawContacts.ACCOUNT_TYPE,
            ContactsContract.RawContacts.ACCOUNT_NAME,
        )

        val selection =
            "(${ContactsContract.RawContacts.ACCOUNT_TYPE} IS NULL OR ${ContactsContract.RawContacts.ACCOUNT_TYPE} != ?)"
        val selectionArgs = arrayOf(DeviceContactAccount.ACCOUNT_TYPE)

        val rawContactCandidates = mutableListOf<Long>()
        contentResolver.query(
            ContactsContract.RawContacts.CONTENT_URI,
            projection,
            selection,
            selectionArgs,
            null,
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val rawContactId = cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts._ID))
                val contactId = cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts.CONTACT_ID))

                val lastUpdated = queryContactLastUpdated(contactId)
                if (lastUpdated > watermarkMs) {
                    rawContactCandidates.add(rawContactId)
                }
            }
        }

        if (rawContactCandidates.isEmpty()) {
            return@withContext
        }

        val existing = db.contactDao().observeAll().first().map { it.toDto() }
        // Built once for the whole loop; findMatch(…, existing) was O(candidates x contacts).
        val matchIndex = DeviceContactMatcher.Index.of(existing)

        for (rawContactId in rawContactCandidates) {
            val candidate = readRawContactSnapshot(rawContactId)
            if (candidate == null) continue

            if (isSystemContact(candidate)) continue

            val candidateEmails = candidate.emails.map { it.value }
            val candidatePhones = candidate.phones.map { it.value }

            val matchedUid = matchIndex.findMatch(candidateEmails, candidatePhones)

            if (matchedUid != null) {
                // Never link a uid to another account's raw contact: our writes go out as a sync
                // adapter, which bypasses CP2's guards. The match still skips the re-import.
                if (candidate.accountType == DeviceContactAccount.ACCOUNT_TYPE) {
                    db.deviceContactLinkDao().upsert(
                        org.kysecurity.mail.data.DeviceContactLinkEntity(
                            uid = matchedUid,
                            rawContactId = rawContactId,
                            deviceUpdatedAtEpochMs = candidate.lastUpdatedEpochMs,
                        ),
                    )
                }
            } else if (candidateEmails.isNotEmpty() || candidatePhones.isNotEmpty()) {
                // The WHOLE email and phone lists: matching only the head created duplicates.
                val alreadyImported = existing.any { existingContact ->
                    existingContact.fn.equals(candidate.fn, ignoreCase = true) &&
                        sharesAnyIdentifier(existingContact, candidateEmails, candidatePhones)
                }
                if (!alreadyImported) {
                    val newDto = candidate.toContactDto(UUID.randomUUID().toString(), 0)
                    syncRepository.queueCreate(newDto)
                }
            }
        }

        settings.setLastForeignScanAtEpochMs(System.currentTimeMillis())
    }

    /** True when [existingContact] and the candidate share any email or phone, normalized the same
     *  way [DeviceContactMatcher] does so "+1 555…" and "555…" are the same number here too. */
    private fun sharesAnyIdentifier(
        existingContact: ContactDto,
        candidateEmails: List<String>,
        candidatePhones: List<String>,
    ): Boolean {
        // Blanks are dropped on both sides, or every blank-valued candidate looks like a match.
        val existingEmails = existingContact.emails
            .mapNotNull { DeviceContactMatcher.normalizeEmail(it.value).takeIf(String::isNotBlank) }.toSet()
        val existingPhones = existingContact.phones
            .mapNotNull { DeviceContactMatcher.normalizePhone(it.value).takeIf(String::isNotBlank) }.toSet()
        return candidateEmails.any {
            DeviceContactMatcher.normalizeEmail(it).let { v -> v.isNotBlank() && v in existingEmails }
        } || candidatePhones.any {
            DeviceContactMatcher.normalizePhone(it).let { v -> v.isNotBlank() && v in existingPhones }
        }
    }

    private suspend fun pushRoomChangesToDevice() = withContext(Dispatchers.IO) {
        val currentRoomContacts = db.contactDao().observeAll().first()
        // One read of the link table for the whole loop rather than a getByUid per contact.
        val linksByUid = db.deviceContactLinkDao().getAll().associateBy { it.uid }

        for (entity in currentRoomContacts) {
            // Policy can change mid-loop: protection can be enabled while this is still running.
            if (!syncPermitted()) return@withContext

            val dto = entity.toDto()
            val existingLink = linksByUid[dto.uid]

            if (existingLink == null) {
                createRawContactForDto(dto)
            } else {
                updateRawContactForDto(dto, existingLink)
            }
        }
    }

    // ContactsContract.CommonDataKinds.Im is deprecated with no replacement mimetype, and the IM
    // rows it names are still the ones present on device.
    @Suppress("DEPRECATION")
    private suspend fun createRawContactForDto(dto: ContactDto) = withContext(Dispatchers.IO) {
        val ops = arrayListOf<android.content.ContentProviderOperation>()

        val rawContactUriBase = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()

        val rawContactUriIndex = ops.size
        ops.add(
            android.content.ContentProviderOperation.newInsert(rawContactUriBase)
                .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
                .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
                .build(),
        )

        val dataUriBase = ContactsContract.Data.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()

        ops.add(
            android.content.ContentProviderOperation.newInsert(dataUriBase)
                .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, dto.fn)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.GIVEN_NAME, dto.givenName)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.FAMILY_NAME, dto.familyName)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.MIDDLE_NAME, dto.middleName)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.PREFIX, dto.prefix)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.SUFFIX, dto.suffix)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.PHONETIC_GIVEN_NAME, dto.phoneticGivenName)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.PHONETIC_FAMILY_NAME, dto.phoneticFamilyName)
                .build(),
        )

        if (!dto.org.isNullOrBlank()) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Organization.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Organization.COMPANY, dto.org)
                    .withValue(ContactsContract.CommonDataKinds.Organization.TITLE, dto.title)
                    .withValue(ContactsContract.CommonDataKinds.Organization.DEPARTMENT, dto.department)
                    .build(),
            )
        }

        if (!dto.notes.isNullOrBlank()) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Note.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Note.NOTE, dto.notes)
                    .build(),
            )
        }

        if (!dto.birthday.isNullOrBlank()) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Event.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Event.START_DATE, dto.birthday)
                    .withValue(ContactsContract.CommonDataKinds.Event.TYPE, 3)
                    .build(),
            )
        }

        for (email in dto.emails) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, email.value)
                    .withValue(ContactsContract.CommonDataKinds.Email.TYPE, email.label ?: "")
                    .build(),
            )
        }

        for (phone in dto.phones) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Phone.NUMBER, phone.value)
                    .withValue(ContactsContract.CommonDataKinds.Phone.TYPE, phone.label ?: "")
                    .build(),
            )
        }

        for (address in dto.addresses) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredPostal.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.STREET, address.street)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.CITY, address.city)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.REGION, address.region)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.POSTCODE, address.postalCode)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.COUNTRY, address.country)
                    .withValue(ContactsContract.CommonDataKinds.StructuredPostal.TYPE, address.label ?: "")
                    .build(),
            )
        }

        for (im in dto.ims) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Im.DATA, im.value)
                    .withValue(ContactsContract.CommonDataKinds.Im.PROTOCOL, ContactsContract.CommonDataKinds.Im.PROTOCOL_CUSTOM)
                    .withValue(
                        ContactsContract.CommonDataKinds.Im.CUSTOM_PROTOCOL,
                        DeviceContactFieldCoding.imCustomProtocolLabel(im.service, im.label),
                    )
                    .build(),
            )
        }

        for (website in dto.websites) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Website.URL, website.value)
                    .withValue(ContactsContract.CommonDataKinds.Website.TYPE, ContactsContract.CommonDataKinds.Website.TYPE_CUSTOM)
                    .withValue(ContactsContract.CommonDataKinds.Website.LABEL, website.label)
                    .build(),
            )
        }

        for (relation in dto.relations) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Relation.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Relation.NAME, relation.name)
                    .withValue(ContactsContract.CommonDataKinds.Relation.TYPE, DeviceContactFieldCoding.relationType(relation.label))
                    .withValue(ContactsContract.CommonDataKinds.Relation.LABEL, DeviceContactFieldCoding.relationCustomLabel(relation.label))
                    .build(),
            )
        }

        // Additional dates beyond birthday -- birthday keeps its own separate Event row above
        // (same MIMETYPE, TYPE_BIRTHDAY), untouched by this loop.
        for (event in dto.events) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Event.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Event.START_DATE, event.date)
                    .withValue(ContactsContract.CommonDataKinds.Event.TYPE, DeviceContactFieldCoding.eventType(event.label))
                    .withValue(ContactsContract.CommonDataKinds.Event.LABEL, DeviceContactFieldCoding.eventCustomLabel(event.label))
                    .build(),
            )
        }

        // Resolved before the batch: GROUP_ROW_ID is a plain value, not a back-reference target.
        val androidGroupRowIds = dto.groupIDs.mapNotNull { groupId ->
            db.groupDao().getById(groupId)?.let { group -> groupLinker.ensureAndroidGroupRowId(groupId, group.name) }
        }
        for (androidGroupRowId in androidGroupRowIds) {
            ops.add(
                android.content.ContentProviderOperation.newInsert(dataUriBase)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawContactUriIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.GroupMembership.GROUP_ROW_ID, androidGroupRowId)
                    .build(),
            )
        }

        val results = runCatching {
            contentResolver.applyBatch(ContactsContract.AUTHORITY, ops)
        }.getOrNull() ?: return@withContext

        if (results.isNotEmpty() && results[0] != null) {
            val rawContactUri = results[0].uri
            val rawContactId = rawContactUri?.lastPathSegment?.toLongOrNull() ?: return@withContext
            db.deviceContactLinkDao().upsert(
                org.kysecurity.mail.data.DeviceContactLinkEntity(
                    uid = dto.uid,
                    rawContactId = rawContactId,
                    deviceUpdatedAtEpochMs = System.currentTimeMillis(),
                ),
            )
        }
    }

    private suspend fun updateRawContactForDto(
        dto: ContactDto,
        link: org.kysecurity.mail.data.DeviceContactLinkEntity,
    ) = withContext(Dispatchers.IO) {
        val currentSnapshot = readRawContactSnapshot(link.rawContactId) ?: return@withContext

        // Never write to a raw contact another account owns; as a sync adapter CP2 skips its guards.
        if (currentSnapshot.accountType != DeviceContactAccount.ACCOUNT_TYPE) {
            db.deviceContactLinkDao().deleteByUid(dto.uid)
            return@withContext
        }

        val mergedNameDisplay = DeviceContactFieldMerge.mergeStringField(
            roomValue = dto.fn,
            deviceValue = currentSnapshot.fn,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedOrg = DeviceContactFieldMerge.mergeStringField(
            roomValue = dto.org,
            deviceValue = currentSnapshot.org,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedNotes = DeviceContactFieldMerge.mergeStringField(
            roomValue = dto.notes,
            deviceValue = currentSnapshot.notes,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedBirthday = DeviceContactFieldMerge.mergeStringField(
            roomValue = dto.birthday,
            deviceValue = currentSnapshot.birthday,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedEmails = DeviceContactFieldMerge.mergeEmailList(
            roomEmails = dto.emails,
            deviceEmails = currentSnapshot.emails,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedPhones = DeviceContactFieldMerge.mergePhoneList(
            roomPhones = dto.phones,
            devicePhones = currentSnapshot.phones,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val mergedAddresses = DeviceContactFieldMerge.mergeAddressList(
            roomAddresses = dto.addresses,
            deviceAddresses = currentSnapshot.addresses,
            roomUpdatedAtEpochMs = dto.updatedAt?.let { DeviceContactConflictResolver.parseIso(it) },
            deviceUpdatedAtEpochMs = link.deviceUpdatedAtEpochMs,
        )

        val ops = arrayListOf<android.content.ContentProviderOperation>()

        val dataUriBase = ContactsContract.Data.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()

        if (mergedNameDisplay != currentSnapshot.fn) {
            ops.add(
                android.content.ContentProviderOperation.newUpdate(dataUriBase)
                    .withSelection(
                        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
                        arrayOf(
                            link.rawContactId.toString(),
                            ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE,
                        ),
                    )
                    .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, mergedNameDisplay ?: "")
                    .build(),
            )
        }

        if (ops.isNotEmpty()) {
            runCatching {
                contentResolver.applyBatch(ContactsContract.AUTHORITY, ops)
            }
        }

        db.deviceContactLinkDao().upsert(
            link.copy(deviceUpdatedAtEpochMs = System.currentTimeMillis()),
        )
    }

    suspend fun deleteDeviceRawContact(uid: String) = withContext(Dispatchers.IO) {
        val link = db.deviceContactLinkDao().getByUid(uid) ?: return@withContext

        // With CALLER_IS_SYNCADAPTER this is a hard delete with no tombstone: check ownership.
        if (!ownsRawContact(link.rawContactId)) {
            db.deviceContactLinkDao().deleteByUid(uid)
            return@withContext
        }

        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        val deleteOps = arrayListOf(
            android.content.ContentProviderOperation.newDelete(uri)
                .withSelection(
                    "${ContactsContract.RawContacts._ID} = ?",
                    arrayOf(link.rawContactId.toString()),
                ).build(),
        )

        runCatching {
            contentResolver.applyBatch(ContactsContract.AUTHORITY, deleteOps)
        }

        db.deviceContactLinkDao().deleteByUid(uid)
    }

    /** These rows sit outside the app sandbox, so neither the wipe nor in-memory Room reaches them. */
    suspend fun deleteAllSyncedDeviceContacts() = syncRepository.syncMutex.withLock {
        withContext(Dispatchers.IO) {
            deleteAllSyncedDeviceContactsLocked()
        }
    }

    /** Takes [ContactSyncRepository.syncMutex]: interleaving leaves rows behind with no link row. */
    private suspend fun deleteAllSyncedDeviceContactsLocked() = withContext(Dispatchers.IO) {
        val uri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
            .appendQueryParameter(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
            .build()
        runCatching {
            contentResolver.delete(
                uri,
                "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
                arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            )
        }.onFailure { android.util.Log.e("DeviceContactSync", "Failed to delete synced raw contacts", it) }

        runCatching { db.deviceContactLinkDao().deleteAll() }
            .onFailure { android.util.Log.e("DeviceContactSync", "Failed to clear device contact links", it) }
    }

    /** CALLER_IS_SYNCADAPTER removes CP2's guards, so ownership is checked, never assumed. */
    private suspend fun ownsRawContact(rawContactId: Long): Boolean = withContext(Dispatchers.IO) {
        contentResolver.query(
            ContactsContract.RawContacts.CONTENT_URI,
            arrayOf(ContactsContract.RawContacts.ACCOUNT_TYPE),
            "${ContactsContract.RawContacts._ID} = ?",
            arrayOf(rawContactId.toString()),
            null,
        )?.use { cursor ->
            cursor.moveToFirst() &&
                cursor.getString(0) == DeviceContactAccount.ACCOUNT_TYPE
        } ?: false
    }

    /** Sweeps legacy link rows pointing at another account's raw contacts, before the first sync. */
    private suspend fun pruneForeignLinks() = withContext(Dispatchers.IO) {
        val stale = db.deviceContactLinkDao().getAll()
            .filter { !ownsRawContact(it.rawContactId) }
            .map { it.rawContactId }
        if (stale.isNotEmpty()) {
            db.deviceContactLinkDao().deleteByRawContactIds(stale)
        }
    }

    private suspend fun queryContactLastUpdated(contactId: Long): Long = withContext(Dispatchers.IO) {
        val projection = arrayOf(ContactsContract.Contacts.CONTACT_LAST_UPDATED_TIMESTAMP)
        contentResolver.query(
            ContactsContract.Contacts.CONTENT_URI,
            projection,
            "${ContactsContract.Contacts._ID} = ?",
            arrayOf(contactId.toString()),
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndexOrThrow(ContactsContract.Contacts.CONTACT_LAST_UPDATED_TIMESTAMP)
                return@withContext cursor.getLong(idx)
            }
        }
        return@withContext 0L
    }

    // See createRawContactForDto: reads back the same deprecated Im rows it writes.
    @Suppress("DEPRECATION")
    private suspend fun readRawContactSnapshot(rawContactId: Long): DeviceRawContactSnapshot? =
        withContext(Dispatchers.IO) {
            val rawContactProjection = arrayOf(
                ContactsContract.RawContacts._ID,
                ContactsContract.RawContacts.CONTACT_ID,
                ContactsContract.RawContacts.ACCOUNT_TYPE,
                ContactsContract.RawContacts.ACCOUNT_NAME,
            )

            val rawContactData = contentResolver.query(
                ContactsContract.RawContacts.CONTENT_URI,
                rawContactProjection,
                "${ContactsContract.RawContacts._ID} = ?",
                arrayOf(rawContactId.toString()),
                null,
            )?.use { cursor ->
                if (cursor.moveToFirst()) {
                    Triple(
                        cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts._ID)),
                        cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts.CONTACT_ID)),
                        cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.RawContacts.ACCOUNT_TYPE)),
                    )
                } else {
                    null
                }
            } ?: return@withContext null

            val (actualRawContactId, contactId, accountType) = rawContactData
            val lastUpdated = queryContactLastUpdated(contactId)

            val dataProjection = arrayOf(
                ContactsContract.Data.MIMETYPE,
                ContactsContract.Data.DATA1,
                ContactsContract.Data.DATA2,
                ContactsContract.Data.DATA3,
                ContactsContract.Data.DATA4,
                ContactsContract.Data.DATA5,
                ContactsContract.Data.DATA6,
                ContactsContract.Data.DATA7,
                ContactsContract.Data.DATA9,
            )

            var fn = ""
            var org: String? = null
            var notes: String? = null
            var birthday: String? = null
            var department: String? = null
            var phoneticGivenName: String? = null
            var phoneticFamilyName: String? = null
            val emails = mutableListOf<ContactFieldDto>()
            val phones = mutableListOf<ContactFieldDto>()
            val addresses = mutableListOf<ContactAddressDto>()
            val ims = mutableListOf<ContactImDto>()
            val websites = mutableListOf<ContactUrlDto>()
            val relations = mutableListOf<ContactRelationDto>()
            val events = mutableListOf<ContactEventDto>()

            contentResolver.query(
                ContactsContract.Data.CONTENT_URI,
                dataProjection,
                "${ContactsContract.Data.RAW_CONTACT_ID} = ?",
                arrayOf(rawContactId.toString()),
                null,
            )?.use { cursor ->
                while (cursor.moveToNext()) {
                    val mimeType = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.MIMETYPE))
                    val data1 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA1)) ?: ""
                    val data2 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA2))
                    val data3 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA3))
                    val data4 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA4))
                    val data5 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA5))
                    val data6 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA6))
                    val data7 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA7))
                    val data9 = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Data.DATA9))

                    when (mimeType) {
                        ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE -> {
                            val given = data2?.takeIf { it.isNotBlank() }
                            val family = data3?.takeIf { it.isNotBlank() }
                            val middle = data4?.takeIf { it.isNotBlank() }
                            val prefix = data5?.takeIf { it.isNotBlank() }
                            val suffix = data6?.takeIf { it.isNotBlank() }
                            fn = listOfNotNull(prefix, given, middle, family, suffix).joinToString(" ")
                            if (fn.isBlank()) fn = data1
                            phoneticGivenName = data7?.takeIf { it.isNotBlank() }
                            phoneticFamilyName = data9?.takeIf { it.isNotBlank() }
                        }

                        ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE -> {
                            if (data1.isNotBlank()) {
                                val label = data2?.takeIf { it.isNotBlank() }
                                emails.add(ContactFieldDto(label = label, value = data1))
                            }
                        }

                        ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE -> {
                            if (data1.isNotBlank()) {
                                val label = data2?.takeIf { it.isNotBlank() }
                                phones.add(ContactFieldDto(label = label, value = data1))
                            }
                        }

                        ContactsContract.CommonDataKinds.Organization.CONTENT_ITEM_TYPE -> {
                            org = data1.takeIf { it.isNotBlank() }
                            department = data5?.takeIf { it.isNotBlank() }
                        }

                        ContactsContract.CommonDataKinds.Note.CONTENT_ITEM_TYPE -> {
                            notes = data1.takeIf { it.isNotBlank() }
                        }

                        ContactsContract.CommonDataKinds.Event.CONTENT_ITEM_TYPE -> {
                            if (data2 == "3") {
                                birthday = data1
                            } else {
                                val typeInt = data2?.toIntOrNull()
                                val label = DeviceContactFieldCoding.eventLabelFromType(typeInt)
                                    ?: data3?.takeIf { it.isNotBlank() }
                                events.add(ContactEventDto(label = label, date = data1))
                            }
                        }

                        ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE -> {
                            if (data1.isNotBlank()) {
                                // Mapped back through the inverse catalog so a recognized
                                // service round-trips intact.
                                val customProtocol = data6?.takeIf { it.isNotBlank() }
                                val service = DeviceContactFieldCoding.imServiceFromCustomProtocolLabel(customProtocol)
                                val label = if (service.isEmpty()) customProtocol else null
                                ims.add(ContactImDto(service = service, label = label, value = data1))
                            }
                        }

                        ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE -> {
                            if (data1.isNotBlank()) {
                                val label = data3?.takeIf { it.isNotBlank() }
                                websites.add(ContactUrlDto(label = label, value = data1))
                            }
                        }

                        ContactsContract.CommonDataKinds.Relation.CONTENT_ITEM_TYPE -> {
                            if (data1.isNotBlank()) {
                                val typeInt = data2?.toIntOrNull()
                                relations.add(
                                    ContactRelationDto(
                                        label = DeviceContactFieldCoding.relationLabelFromType(typeInt),
                                        name = data1,
                                    ),
                                )
                            }
                        }

                        ContactsContract.CommonDataKinds.StructuredPostal.CONTENT_ITEM_TYPE -> {
                            val street = data1?.takeIf { it.isNotBlank() }
                            val city = data3?.takeIf { it.isNotBlank() }
                            val region = data4?.takeIf { it.isNotBlank() }
                            val postalCode = data5?.takeIf { it.isNotBlank() }
                            val country = data6?.takeIf { it.isNotBlank() }
                            val label = data2?.takeIf { it.isNotBlank() }
                            if (street != null || city != null || region != null || postalCode != null || country != null) {
                                addresses.add(
                                    ContactAddressDto(
                                        label = label,
                                        street = street,
                                        city = city,
                                        region = region,
                                        postalCode = postalCode,
                                        country = country,
                                    ),
                                )
                            }
                        }
                    }
                }
            }

            if (fn.isBlank()) {
                return@withContext null
            }

            return@withContext DeviceRawContactSnapshot(
                rawContactId = actualRawContactId,
                contactId = contactId,
                accountType = accountType,
                accountName = null,
                lastUpdatedEpochMs = lastUpdated,
                dirty = false,
                fn = fn,
                org = org,
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
}
