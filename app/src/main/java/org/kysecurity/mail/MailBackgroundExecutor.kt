package org.kysecurity.mail

import android.content.Context
import android.widget.Toast
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.userFacingMessage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Short on purpose: the caller is a teardown that must not block on an unreachable server. */
private const val QUIESCE_TIMEOUT_MS = 2_000L

// Mail mutations outlive the Activity that fired them, so the UI can update optimistically.
object MailBackgroundExecutor {
    private val executor = java.util.concurrent.atomic.AtomicReference<ExecutorService>(
        Executors.newFixedThreadPool(2),
    )

    /** Never lets a task throw out of the pool. An uncaught exception on an executor thread kills
     *  the process, and these tasks run blocking mail I/O whose failure modes include `quiesce()`
     *  interrupting them mid-call — a routine event during a wipe or a protection toggle, not a bug
     *  worth a crash. [submitReporting] already had this; the fire-and-forget path did not. */
    fun submit(task: () -> Unit) {
        executor.get().execute {
            runCatching(task).onFailure { android.util.Log.e("MailBackground", "Background mail task threw", it) }
        }
    }

    /** Stops in-flight work before the DB closes; best-effort, socket reads ignore interrupts. */
    fun quiesce(): Boolean {
        val previous = executor.getAndSet(Executors.newFixedThreadPool(2))
        previous.shutdownNow()
        // awaitTermination returns false on timeout and throws only on interruption; report that.
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

    /** Toasts against the application context: the Activity that started this has usually finished. */
    fun submitReporting(
        context: Context,
        actionLabel: String,
        task: () -> MailOutcome<*>,
    ) {
        val appContext = context.applicationContext
        executor.get().execute {
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
