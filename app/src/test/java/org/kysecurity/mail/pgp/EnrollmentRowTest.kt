package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** Which row the Security page shows. The ordering is as load-bearing as the mapping. */
class EnrollmentRowTest {

    private fun row(
        paired: Boolean = true,
        hostileLocation: Boolean = false,
        hasSecureLockScreen: Boolean = true,
        status: EnrollmentStatus = EnrollmentStatus.NO_BLOB,
        identity: IdentityCheck = IdentityCheck.ClientProtected("164D5B834E7FE927"),
    ) = enrollmentRowFor(paired, hostileLocation, hasSecureLockScreen, status, identity)

    @Test
    fun anUnpairedDeviceShowsNothing() {
        assertEquals(EnrollmentRow.Hidden, row(paired = false))
    }

    @Test
    fun hostileLocationProtectionHidesTheOffer() {
        assertEquals(EnrollmentRow.HostileLocation, row(hostileLocation = true))
    }

    @Test
    fun noSecureLockScreenExplainsItself() {
        assertEquals(EnrollmentRow.NoSecureLockScreen, row(hasSecureLockScreen = false))
    }

    @Test
    fun aClientKeyThatIsNotYetEnrolledOffersTheCeremony() {
        assertEquals(EnrollmentRow.NotEnrolled, row())
    }

    @Test
    fun anEnrolledDeviceOffersRemoval() {
        assertEquals(EnrollmentRow.Enrolled, row(status = EnrollmentStatus.ENROLLED))
    }

    /** A biometric enrollment change or a Keystore invalidation kills the vault key. */
    @Test
    fun anInvalidatedKeyIsSaidRatherThanReadingAsUnEnrolled() {
        assertEquals(EnrollmentRow.KeyInvalidated, row(status = EnrollmentStatus.KEY_INVALIDATED))
    }

    /** The retirement nudge: it names where the key lives rather than saying "unavailable", and
     *  hands the user the action that fixes it. */
    @Test
    fun aServerHeldKeyNamesWhereTheKeyLives() {
        assertEquals(EnrollmentRow.ServerHeldKey, row(identity = IdentityCheck.ServerHeld))
    }

    @Test
    fun anAccountWithNoIdentityIsToldSo() {
        assertEquals(EnrollmentRow.NoIdentity, row(identity = IdentityCheck.NoIdentity))
    }

    /** Decision 10, on the screen this time. */
    @Test
    fun aFailedCheckIsItsOwnRowAndNotNoIdentity() {
        assertEquals(EnrollmentRow.CouldNotCheck, row(identity = IdentityCheck.CouldNotCheck))
    }

    /** Both are local facts, and the spec's table hides them the moment the identity request fails. */
    @Test
    fun localFactsSurviveTheNetworkBeingDown() {
        assertEquals(
            "an invalidated key must be reported even when the account cannot be reached",
            EnrollmentRow.KeyInvalidated,
            row(status = EnrollmentStatus.KEY_INVALIDATED, identity = IdentityCheck.CouldNotCheck),
        )
        assertEquals(
            "removal is a local action and must stay reachable offline",
            EnrollmentRow.Enrolled,
            row(status = EnrollmentStatus.ENROLLED, identity = IdentityCheck.CouldNotCheck),
        )
    }

    /** Hostile Location Protection's contract is that no envelope exists on this device. */
    @Test
    fun hostileLocationOutranksALocalEnrollment() {
        assertEquals(
            EnrollmentRow.HostileLocation,
            row(hostileLocation = true, status = EnrollmentStatus.ENROLLED),
        )
    }

    /** Without a lock screen the vault key cannot exist, so there is nothing to remove and nothing
     *  to offer — say why, and say it before anything that depends on the network. */
    @Test
    fun theLockScreenCheckOutranksTheIdentityCheck() {
        assertEquals(
            EnrollmentRow.NoSecureLockScreen,
            row(hasSecureLockScreen = false, identity = IdentityCheck.CouldNotCheck),
        )
    }

    @Test
    fun theLockScreenCheckOutranksAnEnrolledStatus() {
        assertEquals(
            "without a lock screen the vault key cannot exist, so there is nothing to remove",
            EnrollmentRow.NoSecureLockScreen,
            row(hasSecureLockScreen = false, status = EnrollmentStatus.ENROLLED),
        )
    }

    @Test
    fun theLockScreenCheckOutranksAnInvalidatedStatus() {
        assertEquals(
            "without a lock screen the vault key cannot exist, so there is nothing to report invalidated",
            EnrollmentRow.NoSecureLockScreen,
            row(hasSecureLockScreen = false, status = EnrollmentStatus.KEY_INVALIDATED),
        )
    }
}
