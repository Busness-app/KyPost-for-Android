package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactFieldDto

/**
 * What pushing a [ContactDto] into an already-linked device raw contact has to write.
 *
 * A null member means the device row already carries the merged value, so the batch must not
 * touch it. Kept free of ContentProvider types so the decision is testable on the JVM.
 */
data class DeviceContactUpdatePlan(
    val displayName: String? = null,
    val org: String? = null,
    val notes: String? = null,
    val birthday: String? = null,
    val emails: List<ContactFieldDto>? = null,
    val phones: List<ContactFieldDto>? = null,
    val addresses: List<ContactAddressDto>? = null,
) {
    fun isEmpty(): Boolean = displayName == null && org == null && notes == null &&
        birthday == null && emails == null && phones == null && addresses == null

    companion object {
        /**
         * Runs the same conflict-resolution merge in both directions as `readDeviceChanges`, then
         * keeps only the groups whose merged value differs from what the device already holds.
         *
         * A list merge returns empty only when BOTH sides are empty, so a non-null list here is
         * never a request to clear rows the device has and Room does not.
         */
        fun of(
            dto: ContactDto,
            snapshot: DeviceRawContactSnapshot,
            roomUpdatedAtEpochMs: Long?,
            deviceUpdatedAtEpochMs: Long?,
        ): DeviceContactUpdatePlan {
            fun mergedString(roomValue: String?, deviceValue: String?): String? =
                DeviceContactFieldMerge.mergeStringField(
                    roomValue = roomValue,
                    deviceValue = deviceValue,
                    roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                    deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
                )?.takeIf { it != deviceValue }

            return DeviceContactUpdatePlan(
                displayName = mergedString(dto.fn, snapshot.fn),
                org = mergedString(dto.org, snapshot.org),
                notes = mergedString(dto.notes, snapshot.notes),
                birthday = mergedString(dto.birthday, snapshot.birthday),
                emails = DeviceContactFieldMerge.mergeEmailList(
                    roomEmails = dto.emails,
                    deviceEmails = snapshot.emails,
                    roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                    deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
                ).takeIf { it != snapshot.emails },
                phones = DeviceContactFieldMerge.mergePhoneList(
                    roomPhones = dto.phones,
                    devicePhones = snapshot.phones,
                    roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                    deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
                ).takeIf { it != snapshot.phones },
                addresses = DeviceContactFieldMerge.mergeAddressList(
                    roomAddresses = dto.addresses,
                    deviceAddresses = snapshot.addresses,
                    roomUpdatedAtEpochMs = roomUpdatedAtEpochMs,
                    deviceUpdatedAtEpochMs = deviceUpdatedAtEpochMs,
                ).takeIf { it != snapshot.addresses },
            )
        }
    }
}
