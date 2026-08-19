package org.kysecurity.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, NO_KEY, KEY_INVALIDATED, NO_BLOB }

internal fun EnrollmentStatus.isEnrolled(): Boolean = this == EnrollmentStatus.ENROLLED

/** Probes the keystore, never cached bookkeeping: a cached boolean survives key destruction. */
internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus {
    return try {
        // Inside the try: stored() forces the lazy prefs, and this function must report, never throw.
        val stored = vault.stored()
        vault.secretKey()
        if (stored == null) EnrollmentStatus.NO_BLOB
        else if (vault.openCipher(stored.first) == null) EnrollmentStatus.KEY_INVALIDATED
        else EnrollmentStatus.ENROLLED
    } catch (e: KeyPermanentlyInvalidatedException) {
        EnrollmentStatus.KEY_INVALIDATED
    } catch (e: Exception) {
        EnrollmentStatus.NO_KEY
    }
}
