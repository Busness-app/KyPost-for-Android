package org.kysecurity.mail.contacts.device

import kotlin.test.assertEquals
import org.junit.Test

class DeviceContactPurgeOutcomeTest {

    @Test
    fun deniedPermission_withTheSyncAccountStillPresent_isAFailure() {
        // Rows are owned by the account. The account is here, so rows may be too, and we can no
        // longer reach them — the wipe must report this rather than claim a clean run.
        assertEquals(-1, deniedPermissionRowOutcome(accountExists = true))
    }

    @Test
    fun deniedPermission_withNoSyncAccount_isNotAFailure() {
        // No account means no rows: CP2 hard-deletes an account's raw contacts with it.
        assertEquals(0, deniedPermissionRowOutcome(accountExists = false))
    }
}
