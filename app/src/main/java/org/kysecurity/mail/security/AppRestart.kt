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

/**
 * Rebuilds every process-scoped graph and returns the user to a fresh [MainActivity].
 *
 * Needed whenever a setting requires a new [org.kysecurity.mail.data.DataGraph] — Room decides
 * disk-backed vs in-memory once, at construction time — or after [SecurityWipe] has closed the
 * database out from under the live graph.
 */
object AppRestart {

    /**
     * **Suspending, because the teardown blocks.** [invalidateGraphs] waits up to
     * `MailBackgroundExecutor.QUIESCE_TIMEOUT_MS` on `awaitTermination`, and `ProcessState.resetAll`
     * zeroes up to 64 MB of held attachment plaintext. Every caller of this reached it on the main
     * thread — two of them via an explicit `withContext(Dispatchers.Main)` — so the security-
     * critical path was also a guaranteed multi-hundred-millisecond frozen frame, and an ANR on a
     * slow device.
     */
    suspend fun relaunch(activity: Activity) {
        withContext(Dispatchers.IO) {
            // Statics do not die with the task. Invalidating the graph holders rebuilds everything
            // *they* own, but every process-scoped `object` — the draft cache, the forward handoff,
            // the ephemeral attachment plaintext, the PGP custody cache — survives untouched,
            // because this no longer kills the process. Enumerating them by hand at each call site
            // is what let EphemeralAttachmentBytes hold 64 MB of decrypted mail across a security
            // wipe; the registry is the fix. See [org.kysecurity.mail.ProcessScopedState].
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
        org.kysecurity.mail.MailBackgroundExecutor.quiesce()
        MailRuntime.invalidate()
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
        PushRuntime.invalidate()
        SecurityRuntime.invalidate()
        DataRuntime.invalidate()
    }
}
