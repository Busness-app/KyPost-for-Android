package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Which row the Security page shows.
 *
 * A pure function so all nine outcomes are asserted here rather than through a 706-line Activity.
 * The ordering is as load-bearing as the mapping: two of these rows are LOCAL facts that must
 * survive the network being down, and the spec's table has them last.
 */
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

    /**
     * A real state spec 1 produces — a biometric enrollment change or a Keystore invalidation kills
     * the vault key. It must be *said*, not silently read as un-enrolled: the server may still be
     * telling the user this device can read their mail, and they may decommission the device that
     * actually holds a working copy.
     */
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

    /**
     * **The ordering that matters most.** Both of these are local facts, and both are hidden by the
     * spec's table ordering the moment the identity request fails — which is exactly when a user is
     * most likely to be looking at this screen.
     */
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

    /**
     * Hostile Location Protection outranks everything except pairing. Its contract is that no
     * envelope exists on this device, so an `ENROLLED` probe under it is a contradiction the row
     * must not repeat back to the user as "this device holds a key".
     */
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
}
