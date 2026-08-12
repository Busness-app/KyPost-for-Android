package org.kysecurity.mail.mail

import org.junit.Assert.assertEquals
import org.junit.Test

// A display name is attacker-controlled and is authenticated by nothing: DKIM,
// SPF and DMARC all validate the domain a message was sent from, never the
// human-readable label in front of it. So this arrives intact and aligned:
//
//     From: "Bob <bob@corp.com>" <evil@attacker.tld>
//
// Reply/Reply All/Forward feed from this extractor and carry the quoted
// original, so picking the wrong address out of a From header sends a thread to
// a party who never sent it.
//
// These six vectors are shared verbatim with the webmail
// (frontend/src/lib/addressText.test.ts) and Linux (tests/qml/tst_AddressText.qml)
// clients, so all three agree that the real address is the LAST angle-addr.
class AddressTextTest {
    @Test
    fun ordinaryDisplayNameAndAddress() {
        assertEquals("bob@corp.com", addressFromHeader("Bob <bob@corp.com>"))
    }

    @Test
    fun addressPlantedInTheDisplayNameIsIgnored() {
        assertEquals("bob@corp.com", addressFromHeader("\"evil@attacker.tld\" <bob@corp.com>"))
    }

    // The bug in the old first-match rule: a display name dressed up as an
    // angle-addr won, so the reply went to Bob when the mail genuinely came
    // from the attacker.
    @Test
    fun realAddressWinsOverAMimickingDisplayName() {
        assertEquals("evil@attacker.tld", addressFromHeader("\"Bob <bob@corp.com>\" <evil@attacker.tld>"))
    }

    @Test
    fun bareAddressPassesThrough() {
        assertEquals("bob@corp.com", addressFromHeader("bob@corp.com"))
    }

    @Test
    fun commaInsideAQuotedDisplayName() {
        assertEquals("bob@corp.com", addressFromHeader("\"a, b\" <bob@corp.com>"))
    }

    // Not address-shaped is not an address. The old rule returned the raw value,
    // which put a display name into a recipient field.
    @Test
    fun valueWithNoAddressYieldsEmpty() {
        assertEquals("", addressFromHeader("Unknown sender"))
        assertEquals("", addressFromHeader(""))
    }
}
