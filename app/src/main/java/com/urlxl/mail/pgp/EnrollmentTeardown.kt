package com.urlxl.mail.pgp

import android.content.Context

/**
 * Destroys everything that makes this device able to open its envelope.
 *
 * Two callers, both of which must survive interruption:
 *  - Enabling Hostile Location Protection. An envelope that survived that switch would leave the
 *    account's private key openable by device unlock on a device whose owner has just declared
 *    they are somewhere hostile — the exact disclosure the mode exists to prevent.
 *  - SecurityWipe, reached by too many wrong PIN attempts. A key surviving that would outlive a
 *    wipe nobody chose.
 *
 * Returns the names of the steps that failed; empty means everything is gone. Reporting rather than
 * swallowing is the point: both callers announce success to the user, and a teardown that cannot
 * fail would have them announce it over a live sealed envelope.
 *
 * The vault goes first. If the process dies between the two, what survives is the agreement key,
 * which opens only the relay's transport copy; the reverse order would leave the durable sealed
 * blob — the thing actually worth protecting — behind.
 */
internal object EnrollmentTeardown {
    fun destroy(context: Context): List<String> {
        val failed = mutableListOf<String>()
        failed += EnrollmentVault(context).destroy()
        if (!EnrollmentKeyStore.deleteKeyPair()) failed += "deleteAgreementKey"
        return failed
    }
}
