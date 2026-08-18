package org.kysecurity.mail.contacts.device

import kotlin.test.assertEquals
import org.junit.Test

/**
 * The rule that decides whether a security wipe may claim it destroyed the user's contacts.
 *
 * `DeviceContactPurge.deleteSyncedRows` used to map every `SecurityException` to `0` — "no rows
 * deleted, and that is fine" — on the reasoning that no WRITE_CONTACTS meant this app had never
 * published a row. Runtime permissions are revocable, by the user and (since Android 11) by the OS
 * auto-resetting them for unused apps, so that reasoning is wrong in exactly the case that matters:
 * sync was enabled, rows were published, the permission went away afterwards.
 *
 * `SecurityWipe.deleteSyncedDeviceContactRows` treats `0` as success and only a negative count as a
 * failure, so the wipe reported `Complete` while the user's whole address book was still in
 * ContactsContract — outside the app sandbox, readable by every app holding READ_CONTACTS and
 * visible in the phone's own Contacts app.
 */
class DeviceContactPurgeOutcomeTest {

    @Test
    fun deniedPermission_withTheSyncAccountStillPresent_isAFailure() {
        // Rows are owned by the account. The account is here, so rows may be too, and we can no
        // longer reach them — the wipe must report this rather than claim a clean run.
        assertEquals(-1, deniedPermissionRowOutcome(accountExists = true))
    }

    @Test
    fun deniedPermission_withNoSyncAccount_isNotAFailure() {
        // No account means no rows can exist: CP2 hard-deletes an account's raw contacts when the
        // account goes, and nothing else writes under this account type. Reporting a failure here
        // would make every wipe on a device that never enabled sync — the default — read as
        // Incomplete, which is the over-correction the original comment was guarding against.
        assertEquals(0, deniedPermissionRowOutcome(accountExists = false))
    }
}
