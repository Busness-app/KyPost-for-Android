package org.kysecurity.mail.push

import androidx.biometric.BiometricManager
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The fail-open boundary on [MfaApprovalActivity]'s authentication gate.
 *
 * Approving a sign-in is the highest-value action in this app, and the screen is deliberately
 * exempt from the app lock — so "no authenticator is available" is the one condition that lets both
 * buttons go live untouched. It has to mean exactly that, and nothing adjacent to it.
 */
class MfaAuthenticatorAvailabilityTest {

    @Test
    fun noHardwareOrNoEnrolmentIsTheOnlyWayToFailOpen() {
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE))
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED))
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED))
    }

    /**
     * The regression this file exists for. A sensor that is merely busy, or a status the platform
     * could not determine, used to be read as "this device has no screen lock" and enabled approve
     * and deny with no authentication whatsoever — on a device that does have one.
     */
    @Test
    fun transientAndIndeterminateStatusesDoNotFailOpen() {
        assertFalse(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE))
        assertFalse(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_STATUS_UNKNOWN))
        assertFalse(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED))
    }

    @Test
    fun successIsNotAMissingAuthenticator() {
        assertFalse(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_SUCCESS))
    }

    /** An unrecognised future status must take the prompt path, which fails closed via
     *  `onAuthenticationError`, rather than the fail-open path. */
    @Test
    fun anUnknownStatusCodeDoesNotFailOpen() {
        assertFalse(mfaHasNoAuthenticator(Int.MIN_VALUE))
        assertFalse(mfaHasNoAuthenticator(9_999))
    }
}
