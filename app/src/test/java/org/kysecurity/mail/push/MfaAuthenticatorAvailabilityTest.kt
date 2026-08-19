package org.kysecurity.mail.push

import androidx.biometric.BiometricManager
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaAuthenticatorAvailabilityTest {

    @Test
    fun noHardwareOrNoEnrolmentIsTheOnlyWayToFailOpen() {
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE))
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED))
        assertTrue(mfaHasNoAuthenticator(BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED))
    }

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

    @Test
    fun anUnknownStatusCodeDoesNotFailOpen() {
        assertFalse(mfaHasNoAuthenticator(Int.MIN_VALUE))
        assertFalse(mfaHasNoAuthenticator(9_999))
    }
}
