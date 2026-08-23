package org.kysecurity.mail.security

import android.app.Activity
import android.content.Intent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.push.PushRuntime

object AppRestart {

    /** Suspending: teardown awaits executor termination and zeroes held attachment plaintext. */
    suspend fun relaunch(activity: Activity) {
        withContext(Dispatchers.IO) {
            // The process survives, so process-scoped state needs an explicit reset.
            org.kysecurity.mail.ProcessState.resetAll()
            invalidateGraphs()
        }
        withContext(Dispatchers.Main) {
            activity.startActivity(
                Intent(activity, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
            )
            activity.finishAffinity()
        }
    }

    /** [DataRuntime] backs the three graphs above it, so those must be dropped too — otherwise
     *  they keep a DAO handle on the closed database. */
    private fun invalidateGraphs() {
        // Quiesce BEFORE dropping DataRuntime, which closes the database it owns. Mail mutations are
        // deliberately fired on a pool that outlives the screen that started them, so closing the
        // database out from under one is an uncaught exception on a non-UI thread — a process kill.
        // Suspended for the whole teardown, not just up to it: submissions in between would run
        // against graphs that are being dropped. `finally`, because the process survives a relaunch
        // and the screen it lands on still needs mail actions to work.
        org.kysecurity.mail.MailBackgroundExecutor.quiesce()
        try {
            MailRuntime.invalidate()
            DeviceContactsRuntime.invalidate()
            ContactsRuntime.invalidate()
            PushRuntime.invalidate()
            SecurityRuntime.invalidate()
            DataRuntime.invalidate()
        } finally {
            org.kysecurity.mail.MailBackgroundExecutor.resume()
        }
    }
}
