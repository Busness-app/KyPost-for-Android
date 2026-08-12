package org.kysecurity.mail.security

import android.app.Activity
import android.content.Intent
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.push.PushRuntime

/**
 * Rebuilds every process-scoped graph and returns the user to a fresh [MainActivity].
 *
 * Needed whenever a setting requires a new [org.kysecurity.mail.data.DataGraph] — Room decides
 * disk-backed vs in-memory once, at construction time — or after [SecurityWipe] has closed the
 * database out from under the live graph.
 *
 * This used to schedule an `AlarmManager` alarm a few hundred ms out and then call
 * `Process.killProcess`. That was unreliable in exactly the moment it mattered: the alarm used
 * `ELAPSED_REALTIME` (which does not fire while the device is dozing) and `set()` (inexact, and
 * deferrable by minutes under App Standby), so toggling a security setting could make the app
 * vanish and not come back. Invalidating the graph holders achieves the same thing synchronously,
 * with no permission, no alarm, and no window where the process is gone. `CLEAR_TASK` plus
 * [Activity.finishAffinity] destroys every Activity that could still hold a reference to the old
 * graph's objects.
 */
object AppRestart {
    fun relaunch(activity: Activity) {
        // Statics do not die with the task. Invalidating the graph holders rebuilds everything
        // *they* own, but every process-scoped `object` — the draft cache, the forward handoff, the
        // ephemeral attachment plaintext, the PGP custody cache, the notification bookkeeping —
        // survives untouched, because this no longer kills the process. Enumerating them by hand at
        // each call site is what let EphemeralAttachmentBytes hold 64 MB of decrypted mail across a
        // security wipe; the registry is the fix. See [org.kysecurity.mail.ProcessScopedState].
        org.kysecurity.mail.ProcessState.resetAll()
        invalidateGraphs()
        activity.startActivity(
            Intent(activity, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        activity.finishAffinity()
    }

    /** [DataRuntime] backs the three graphs above it, so those must be dropped too — otherwise
     *  they keep a DAO handle on the closed database. */
    private fun invalidateGraphs() {
        MailRuntime.invalidate()
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
        PushRuntime.invalidate()
        SecurityRuntime.invalidate()
        DataRuntime.invalidate()
    }
}
