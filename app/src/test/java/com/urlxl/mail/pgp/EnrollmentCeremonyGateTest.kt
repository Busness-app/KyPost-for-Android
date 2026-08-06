package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Everything that must happen — or must NOT happen — before a keypair exists.
 *
 * The shared claim under all of these: a blocked ceremony leaves nothing behind. `newKeyPair()`
 * destroys any previous key and mints a fresh one, so calling it speculatively and giving up is not
 * free; and publishing a key the user then cannot use leaves the account's device row advertising an
 * enrollment key for a device that has none.
 */
class EnrollmentCeremonyGateTest {

    /**
     * Hostile Location Protection's contract is that no envelope exists on this device. Enrolling
     * under it would create exactly the artefact its teardown destroys.
     */
    @Test
    fun hostileLocationProtectionBlocksBeforeAnyKeyIsMinted() = runBlocking {
        val ports = FakePorts(hostileLocation = true)
        val ceremony = ports.ceremony()

        ceremony.run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.HOSTILE_LOCATION),
            ports.states.last(),
        )
        assertEquals("no keypair may be minted", 0, ports.keys.newKeyPairCalls)
        assertEquals("nothing may be published", 0, ports.transport.publishedKeys.size)
    }

    /**
     * `EnrollmentVault.ensureKey()` returns false without a secure lock screen, by design — the
     * envelope's protection *is* the lock screen. Saying so at the entry beats a biometric prompt
     * that cannot be satisfied after the user has already read a code aloud.
     */
    @Test
    fun noSecureLockScreenBlocksBeforeAnyKeyIsMinted() = runBlocking {
        val ports = FakePorts(secureLockScreen = false)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NO_SECURE_LOCK_SCREEN),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
        assertTrue("no identity request may be made", ports.identity.checkCalls == 0)
    }

    /**
     * Test 8 from the original 2b handoff — enrollment before an identity exists.
     *
     * There is nothing for the browser to seal, so a ceremony started here would show the user a
     * code and poll for five minutes against an envelope that can never arrive.
     */
    @Test
    fun anAccountWithNoIdentityIsUnavailableAndMintsNothing() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NO_IDENTITY),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /** A server-held key needs no device copy; the browser is where that account's key lives. */
    @Test
    fun aServerHeldKeyIsUnavailable() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.ServerHeld)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.SERVER_HELD_KEY),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /**
     * The distinction decision 10 exists to protect. A failed check must not collapse into
     * [UnavailableReason.NO_IDENTITY]: those two render as different sentences to the user, and one
     * of them tells a user with a perfectly good identity to go and make another.
     */
    @Test
    fun aFailedCheckIsCouldNotCheckAndNotNoIdentity() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.CouldNotCheck)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.COULD_NOT_CHECK),
            ports.states.last(),
        )
    }

    @Test
    fun anUnpairedDeviceIsUnavailableAndMintsNothing() = runBlocking {
        val ports = FakePorts(deviceIdValue = null)

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED),
            ports.states.last(),
        )
        assertEquals(0, ports.keys.newKeyPairCalls)
    }

    /** The first thing the user sees is the check, not a blank screen. */
    @Test
    fun theFirstStateIsCheckingIdentity() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.CheckingIdentity, ports.states.first())
    }

    /**
     * Ordering matters, not just outcomes. Hostile Location Protection is a local declaration that
     * this network is hostile, so answering it must not require a request to a server on that
     * network first.
     */
    @Test
    fun hostileLocationIsCheckedBeforeTheIdentityRequest() = runBlocking {
        val ports = FakePorts(hostileLocation = true, identityResult = IdentityCheck.ClientProtected("AA"))

        ports.ceremony().run()

        assertTrue("no identity request may be made", ports.identity.checkCalls == 0)
    }
}
