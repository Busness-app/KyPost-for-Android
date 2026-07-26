package com.urlxl.mail.pgp

import kotlin.test.assertEquals
import org.junit.Test

class PgpComposeStateTest {

    @Test
    fun serverCustodyWithIdentity_offersBoth() {
        assertEquals(
            PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = true, protection = "server"),
        )
    }

    /** No identity means plaintext send only (spec's custody table). No toggles, and not a
     *  handoff either — there is no key held anywhere to hand off to. */
    @Test
    fun noIdentity_offersNothingAndIsNotAHandoff() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = false, protection = ""),
        )
    }

    /** The key is unwrapped only in the browser, from a password this device never learns. */
    @Test
    fun clientCustody_offersNeitherAndHandsOff() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
            pgpComposeStateOf(hasIdentity = true, protection = "client"),
        )
    }

    /** Couldn't check is not "no". A null protection means bootstrap failed: hide everything
     *  rather than guessing. Guessing "server" would offer a toggle that 409s, and guessing
     *  "client" would send people to webmail for no reason. */
    @Test
    fun unknownBootstrap_hidesEverything() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = null, protection = null),
        )
    }

    /** An unrecognized protection value degrades to "not server" rather than being treated as
     *  server-custody — the spec's parse-permissively rule. */
    @Test
    fun unknownProtectionValue_degradesRatherThanGuessing() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = true, protection = "quantum"),
        )
    }
}
