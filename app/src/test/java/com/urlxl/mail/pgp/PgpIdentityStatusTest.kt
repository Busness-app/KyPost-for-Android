package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Covers [pgpIdentityFromMintResult] — the pure mapping [hasPgpIdentity] uses to turn a
 *  [PgpQrClient.mintToken] outcome into "does this account have a PGP identity". */
class PgpIdentityStatusTest {

    @Test
    fun success_mapsToTrue() {
        val result = PgpQrTokenResult.Success(PgpQrTokenDto(token = "t", expiresAt = "e", url = "u"))
        assertEquals(true, pgpIdentityFromMintResult(result))
    }

    @Test
    fun noIdentity_mapsToFalse() {
        val result = PgpQrTokenResult.NoIdentity("no pgp identity configured yet")
        assertEquals(false, pgpIdentityFromMintResult(result))
    }

    @Test
    fun unauthorized_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.Unauthorized("bad secret")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    @Test
    fun serviceUnavailable_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.ServiceUnavailable("pairing not configured")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    @Test
    fun retryable_mapsToNull_notFalse() {
        val result = PgpQrTokenResult.Retryable("network error")
        assertEquals(null, pgpIdentityFromMintResult(result))
    }

    /**
     * The account's own fingerprint comes from the bootstrap response's `publicKey`, hashed
     * locally. The self-contact's `pgpKey` column — what the QR screen used to read — is an
     * ordinary, independently-editable contact field with no connection to the account's real PGP
     * identity (see [com.urlxl.mail.contacts.contactHasLinkedPgpKey]), so it is empty for every
     * user who never manually attached a key to their own contact row, and the screen showed
     * "your fingerprint is unavailable" to everyone.
     */
    @Test
    fun bootstrapWithPublicKey_yieldsLocallyComputedFingerprint() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = TestPgpKey.ARMORED,
        )

        assertEquals(TestPgpKey.FINGERPRINT, ownFingerprintFromBootstrap(result))
    }

    /** Never render the server's own `fingerprint` string: it is a claim in the same response as
     *  the key, with no cryptographic tie to it. An unparseable key is "unavailable", not a
     *  fingerprint borrowed from elsewhere in the body. */
    @Test
    fun bootstrapWithUnparseableKey_isNull() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----",
        )

        assertNull(ownFingerprintFromBootstrap(result))
    }

    @Test
    fun bootstrapWithoutIdentity_isNull() {
        assertNull(ownFingerprintFromBootstrap(PgpBootstrapResult.Success(false, "", "")))
    }

    @Test
    fun failedBootstrap_isNull() {
        assertNull(ownFingerprintFromBootstrap(PgpBootstrapResult.Failed("no route to host")))
    }
}
