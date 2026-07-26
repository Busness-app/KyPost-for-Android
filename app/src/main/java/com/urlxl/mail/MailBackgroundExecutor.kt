package com.urlxl.mail

import android.content.Context
import android.widget.Toast
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.userFacingMessage
import java.util.concurrent.Executors

// State-changing mail actions (mark read, archive, delete, move) are fired here instead of an
// Activity-scoped executor so the IMAP round trip keeps running after the screen that triggered
// it finishes, letting the UI update optimistically instead of waiting on the network.
object MailBackgroundExecutor {
    private val executor = Executors.newFixedThreadPool(2)

    fun submit(task: () -> Unit) {
        executor.execute(task)
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
