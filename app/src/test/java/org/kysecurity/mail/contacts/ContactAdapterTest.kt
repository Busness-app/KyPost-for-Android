package org.kysecurity.mail.contacts

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Covers [contactHasLinkedPgpKey] — regression test for the self-contact's "PGP" badge showing
 *  "not linked" even when the account has a real PGP identity on the server. The self-contact's own
 *  `pgpKey` field (see `contacts.go`/`pgp_qr_handlers.go` on the server) is a normal, independently
 *  editable contact field with no connection to the account's actual PGP identity, so the badge must
 *  also honor the account-level [hasPgpIdentity] signal for that one contact specifically. */
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
