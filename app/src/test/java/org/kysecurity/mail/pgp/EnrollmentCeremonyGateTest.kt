package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A blocked ceremony leaves nothing behind: `newKeyPair()` destroys any previous key. */
class EnrollmentCeremonyGateTest {

    /** Hostile Location Protection's contract is that no envelope exists on this device. */
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

    /** `EnrollmentVault.ensureKey()` returns false without a secure lock screen, by design. */
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

    /** With no identity there is nothing for the browser to seal. */
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

    /** Decision 10: the two render as different sentences to the user. */
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

    /** Answering a local declaration must not require a request to the hostile network. */
    @Test
    fun hostileLocationIsCheckedBeforeTheIdentityRequest() = runBlocking {
        val ports = FakePorts(hostileLocation = true, identityResult = IdentityCheck.ClientProtected("AA"))

        ports.ceremony().run()

        assertTrue("no identity request may be made", ports.identity.checkCalls == 0)
    }
}
