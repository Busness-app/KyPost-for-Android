package com.urlxl.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, NO_KEY, KEY_INVALIDATED, NO_BLOB }

internal fun EnrollmentStatus.isEnrolled(): Boolean = this == EnrollmentStatus.ENROLLED

/**
 * Whether this device can still open its local envelope — reported to the server as
 * `encryptionEnrolled`, and rendered by the browser as "this device can read your encrypted mail".
 *
 * Probes the **keystore**, not our own bookkeeping. A cached boolean would survive an app reinstall
 * or a biometric-enrollment change, both of which destroy the key without any code of ours running,
 * and the Security page would then tell the user a device can read their mail when it can read
 * nothing.
 *
 * Uses `Cipher.init`, which needs no user authentication: this runs from a background worker where
 * nothing can show a prompt. A key that is merely locked initialises fine; only a permanently
 * invalidated one throws.
 */
internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus {
    val stored = vault.stored()
    return try {
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
