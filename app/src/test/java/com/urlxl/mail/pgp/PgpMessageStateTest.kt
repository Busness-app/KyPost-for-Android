package com.urlxl.mail.pgp

import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.Test

class PgpMessageStateTest {

    @Test
    fun noPgpContent_isNone() {
        assertEquals(PgpMessageState.NONE, pgpMessageStateOf(false, "", "<p>hi</p>"))
        assertEquals(PgpMessageState.NONE, pgpMessageStateOf(false, "", null))
    }

    /** The client-protected shape: the server sets the flag, decrypts nothing, and reports no
     *  error because nothing went wrong — it simply has no key. */
    @Test
    fun encryptedWithNoErrorAndNoBody_isClientProtected() {
        assertEquals(PgpMessageState.CLIENT_PROTECTED, pgpMessageStateOf(true, "", null))
        assertEquals(PgpMessageState.CLIENT_PROTECTED, pgpMessageStateOf(true, "", ""))
        assertEquals(PgpMessageState.CLIENT_PROTECTED, pgpMessageStateOf(true, "   ", "  "))
    }

    @Test
    fun encryptedWithError_isDecryptFailed() {
        assertEquals(PgpMessageState.DECRYPT_FAILED, pgpMessageStateOf(true, "no pgp identity configured", null))
    }

    /**
     * The error wins over an empty body. Both conditions hold at once for a failed decrypt, and
     * reading it as CLIENT_PROTECTED would send the user to webmail for a message that fails
     * there too, hiding a reason the server already gave us.
     */
    @Test
    fun errorTakesPrecedenceOverMissingBody() {
        assertEquals(PgpMessageState.DECRYPT_FAILED, pgpMessageStateOf(true, "bad key", ""))
    }

    @Test
    fun encryptedWithBody_isDecryptedByServer() {
        assertEquals(PgpMessageState.DECRYPTED_BY_SERVER, pgpMessageStateOf(true, "", "<p>plaintext</p>"))
    }

    /** Only the states that yield nothing readable get a row marker — a server-mode mailbox would
     *  otherwise carry a symbol on most rows that the user can do nothing with. */
    @Test
    fun onlyUnreadableStatesGetARowMarker() {
        assertEquals("🔒", pgpRowMarker(PgpMessageState.CLIENT_PROTECTED))
        assertEquals("⚠", pgpRowMarker(PgpMessageState.DECRYPT_FAILED))
        assertNull(pgpRowMarker(PgpMessageState.DECRYPTED_BY_SERVER))
        assertNull(pgpRowMarker(PgpMessageState.NONE))
    }

    @Test
    fun serverVerifiedNeverClaimsTheUserConfirmedTheKey() {
        // The relay's two booleans cannot tell a fingerprint-confirmed key from an
        // Autocrypt-harvested one, so the mapping takes the weaker claim. Promoting this to
        // VERIFIED_CONFIRMED would reintroduce the exact over-claim Part 0.2 removed.
        assertEquals(
            PgpSignatureState.VERIFIED_SEEN_BEFORE,
            pgpSignatureStateOf(pgpSigned = true, pgpVerified = true),
        )
    }

    @Test
    fun aChangedKeyMarksTheRow() {
        assertEquals("⚠", pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.KEY_CHANGED))
    }

    @Test
    fun anUnknownSignerDoesNotMarkTheRow() {
        // It is the ordinary state for anyone not yet in the address book. A glyph on most rows
        // carries nothing the user can act on — the same reason DECRYPTED_BY_SERVER is unmarked.
        assertNull(pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.SIGNER_UNKNOWN))
    }
}
