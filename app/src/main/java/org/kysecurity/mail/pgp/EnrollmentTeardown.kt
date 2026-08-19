package org.kysecurity.mail.pgp

import android.content.Context

/** Destroys everything that can open this device's envelope. The vault goes first, deliberately. */
internal object EnrollmentTeardown {
    fun destroy(context: Context): List<String> {
        val failed = mutableListOf<String>()
        failed += EnrollmentVault(context).destroy()
        if (!EnrollmentKeyStore.deleteKeyPair()) failed += "deleteAgreementKey"
        return failed
    }

    /** [destroy] plus the correction to the server, for "Remove from this device". */
    fun destroyAndReport(context: Context): List<String> {
        val leftBehind = destroy(context)
        EnrollmentStateWorker.enqueue(context)
        return leftBehind
    }
}
