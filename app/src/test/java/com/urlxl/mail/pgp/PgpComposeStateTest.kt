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

    /** Not enrolled, so this device holds no key: unchanged behaviour, webmail is the only route. */
    @Test
    fun clientCustody_offersNeitherAndHandsOff() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
            pgpComposeStateOf(hasIdentity = true, protection = "client"),
        )
    }

    /**
     * An enrolled device holds the account's private key, so it can encrypt and sign locally.
     *
     * [PgpComposeState.clientSide] is what routes the send to `/api/mail/send-pgp` instead of
     * `/api/mail/send`; without it the compose screen would offer toggles and then post them to the
     * endpoint that answers 409 for exactly this account type.
     */
    @Test
    fun clientCustodyEnrolled_offersBothAndEncryptsOnThisDevice() {
        assertEquals(
            PgpComposeState(
                canEncrypt = true,
                canSign = true,
                handoffToWebmail = false,
                clientSide = true,
            ),
            pgpComposeStateOf(
                hasIdentity = true,
                protection = "client",
                deviceEnrolled = true,
                accountAddress = "me@example.invalid",
            ),
        )
    }

    /**
     * Enrolled but no account address: every delivery's `From` must equal the authorized address,
     * and there is none to write. Offering Send here would build ciphertext the relay 403s, so this
     * degrades to the handoff instead.
     */
    @Test
    fun clientCustodyEnrolledWithoutAnAccountAddress_handsOffInstead() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
            pgpComposeStateOf(
                hasIdentity = true,
                protection = "client",
                deviceEnrolled = true,
                accountAddress = "   ",
            ),
        )
    }

    /** Server custody is never the client-side path, however enrolled the device is: the server
     *  holds that key and `/api/pgp/recipients/resolve` refuses this account outright. */
    @Test
    fun serverCustody_isNeverClientSideEvenWhenEnrolled() {
        assertEquals(
            PgpComposeState(
                canEncrypt = true,
                canSign = true,
                handoffToWebmail = false,
                clientSide = false,
            ),
            pgpComposeStateOf(
                hasIdentity = true,
                protection = "server",
                deviceEnrolled = true,
                accountAddress = "me@example.invalid",
            ),
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
