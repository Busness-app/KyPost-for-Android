package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** Covers [identityCheckFrom] — the pure "degrade, never guess" mapping [AndroidIdentitySource.check]
 *  uses to turn one `GET /api/pgp/bootstrap` response into an [IdentityCheck]. */
class IdentityCheckFromTest {

    @Test
    fun failedBootstrap_couldNotCheck() {
        assertEquals(
            IdentityCheck.CouldNotCheck,
            identityCheckFrom(PgpBootstrapResult.Failed("no route to host")),
        )
    }

    @Test
    fun noIdentity_noIdentity() {
        assertEquals(
            IdentityCheck.NoIdentity,
            identityCheckFrom(PgpBootstrapResult.Success(hasIdentity = false, protection = "", publicKey = "")),
        )
    }

    @Test
    fun clientProtectedWithParseableKey_yieldsFingerprintFromKeyBytes() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = TestPgpKey.ARMORED,
        )

        assertEquals(IdentityCheck.ClientProtected(TestPgpKey.FINGERPRINT), identityCheckFrom(result))
    }

    /** A user's own key must never be described as absent: an identity whose key will not parse
     *  cannot be bound into an envelope's AAD, so it degrades to "could not check" rather than
     *  being reported as [IdentityCheck.NoIdentity]. */
    @Test
    fun clientProtectedWithUnparseableKey_couldNotCheck_notNoIdentity() {
        val result = PgpBootstrapResult.Success(
            hasIdentity = true,
            protection = "client",
            publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----",
        )

        assertEquals(IdentityCheck.CouldNotCheck, identityCheckFrom(result))
    }

    @Test
    fun serverHeld_serverHeld() {
        val result = PgpBootstrapResult.Success(hasIdentity = true, protection = "server", publicKey = "")
        assertEquals(IdentityCheck.ServerHeld, identityCheckFrom(result))
    }

    /** An unrecognised protection value degrades to "could not check" rather than being guessed as
     *  client-protected: guessing wrong starts a ceremony that can only end at a failed GCM open,
     *  this feature's one alarm. */
    @Test
    fun unrecognisedProtection_degradesRatherThanGuessing() {
        val result = PgpBootstrapResult.Success(hasIdentity = true, protection = "quantum", publicKey = "")
        assertEquals(IdentityCheck.CouldNotCheck, identityCheckFrom(result))
    }
}
