package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.BuildConfig
import kotlin.test.Test
import kotlin.test.assertEquals

/** The account type is global to the device and signature-bound: two installs claiming the same
 *  one collide, and only the first authenticator wins. Deriving it from the applicationId is what
 *  lets the play, github and fdroid builds coexist — this pins the derivation so a later edit
 *  cannot quietly return to a literal. */
class DeviceContactAccountTest {
    @Test
    fun accountTypeIsDerivedFromTheApplicationId() {
        assertEquals("${BuildConfig.APPLICATION_ID}.contacts", DeviceContactAccount.ACCOUNT_TYPE)
    }

    @Test
    fun theDefaultFlavorKeepsTodaysAccountType() {
        // Only true for the play flavor, which must not migrate existing installs' device account.
        if (BuildConfig.APPLICATION_ID == "org.kysecurity.mail") {
            assertEquals("org.kysecurity.mail.contacts", DeviceContactAccount.ACCOUNT_TYPE)
        }
    }
}
