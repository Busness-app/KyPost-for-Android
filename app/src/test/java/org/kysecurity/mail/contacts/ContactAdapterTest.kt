package org.kysecurity.mail.contacts

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The self-contact's own `pgpKey` field is unrelated to the account's real PGP identity. */
class ContactAdapterTest {

    @Test
    fun nonSelfContact_withPgpKey_isLinked() {
        assertTrue(contactHasLinkedPgpKey(pgpKey = "-----BEGIN PGP...", isSelf = false, selfHasPgpIdentity = null))
    }

    @Test
    fun nonSelfContact_withoutPgpKey_isNotLinked_regardlessOfSelfIdentityFlag() {
        assertFalse(contactHasLinkedPgpKey(pgpKey = null, isSelf = false, selfHasPgpIdentity = true))
    }

    @Test
    fun selfContact_withoutOwnPgpKeyField_butConfirmedServerIdentity_isLinked() {
        assertTrue(contactHasLinkedPgpKey(pgpKey = null, isSelf = true, selfHasPgpIdentity = true))
    }

    @Test
    fun selfContact_withoutOwnPgpKeyField_andNoConfirmedIdentity_isNotLinked() {
        assertFalse(contactHasLinkedPgpKey(pgpKey = null, isSelf = true, selfHasPgpIdentity = false))
    }

    @Test
    fun selfContact_withoutOwnPgpKeyField_andUnknownIdentityStatus_isNotLinked() {
        assertFalse(contactHasLinkedPgpKey(pgpKey = null, isSelf = true, selfHasPgpIdentity = null))
    }

    @Test
    fun selfContact_withOwnPgpKeyField_isLinked_evenWithoutConfirmedIdentity() {
        assertTrue(contactHasLinkedPgpKey(pgpKey = "-----BEGIN PGP...", isSelf = true, selfHasPgpIdentity = false))
    }
}
