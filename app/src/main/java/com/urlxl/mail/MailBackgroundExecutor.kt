package com.urlxl.mail

import android.content.Context
import android.widget.Toast
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.userFacingMessage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** How long [MailBackgroundExecutor.quiesce] waits for in-flight mail work to stop before giving
 *  up on it. Short: these tasks are network calls that may be blocked in a socket read, and the
 *  caller is a destructive teardown that must not be held up by an unreachable server. */
private const val QUIESCE_TIMEOUT_MS = 2_000L

// State-changing mail actions (mark read, archive, delete, move) are fired here instead of an
// Activity-scoped executor so the IMAP round trip keeps running after the screen that triggered
// it finishes, letting the UI update optimistically instead of waiting on the network.
object MailBackgroundExecutor {
    @Volatile
    private var executor: ExecutorService = Executors.newFixedThreadPool(2)

    fun submit(task: () -> Unit) {
        executor.execute(task)
    }

    /**
     * Stops in-flight mail work and hands back a fresh pool.
     *
     * Called before the database is closed and deleted. `SingletonGraph.invalidate()` only makes the
     * *next* `get()` rebuild — every task already running holds the old `AppDatabase`, so closing it
     * out from under them threw `IllegalStateException` on a pool thread, which is an uncaught
     * exception on a non-UI thread, which is a process kill. This is the largest source of that:
     * these tasks are fired precisely so they outlive the screen that started them.
     *
     * Best-effort by construction. `shutdownNow` interrupts, and a thread blocked inside a socket
     * read does not observe an interrupt — hence the bounded wait and the unconditional rebuild.
     * What it buys is that the common case (a task between network calls, or queued and not yet
     * started) is torn down rather than left pointing at a closed database.
     */
    fun quiesce(): Boolean {
        val previous = executor
        executor = Executors.newFixedThreadPool(2)
        previous.shutdownNow()
        // `awaitTermination` returns false on timeout and throws only on interruption, so wrapping
        // it in `runCatching` and inspecting only the failure branch discarded the one answer that
        // matters: "threads are still running against the database you are about to close". That is
        // the uncaught-exception-on-a-pool-thread process kill this function exists to prevent, and
        // it was being silently accepted. Report it instead — the caller still proceeds (a wipe
        // cannot be held hostage by a socket read), but it can now say so.
        val settled = try {
            previous.awaitTermination(QUIESCE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!settled) {
            android.util.Log.w("MailBackground", "Mail work did not quiesce within ${QUIESCE_TIMEOUT_MS}ms")
        }
        return settled
    }

    /**
     * Runs a mail mutation and reports failure to the user.
     *
     * Every caller of [submit] used to discard the returned [MailOutcome]. The UI removed the row
     * optimistically, so a 401, a 502 or a certificate-pin mismatch was completely invisible: the
     * user believed the message was archived or deleted on the server, and it reappeared on the
     * next full resync with no explanation. Optimistic UI is only honest if the pessimistic case
     * is surfaced.
     *
     * The toast is posted against the application context because the Activity that started this
     * has usually already finished — that is the whole reason this executor exists.
     */
    fun submitReporting(
        context: Context,
        actionLabel: String,
        task: () -> MailOutcome<*>,
    ) {
        val appContext = context.applicationContext
        executor.execute {
            val outcome = runCatching { task() }.getOrElse { error ->
                android.util.Log.e("MailBackground", "$actionLabel threw", error)
                MailOutcome.UpstreamFailure(error.message ?: "Unexpected error")
            }
            if (outcome is MailOutcome.Success) return@execute
            val reason = outcome.userFacingMessage().orEmpty()
            android.util.Log.w("MailBackground", "$actionLabel failed: $reason")
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                Toast.makeText(
                    appContext,
                    appContext.getString(R.string.mail_action_failed, actionLabel, reason),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }
}
