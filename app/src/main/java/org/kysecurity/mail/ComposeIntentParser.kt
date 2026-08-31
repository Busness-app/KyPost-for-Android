package org.kysecurity.mail

import android.content.Intent
import android.net.MailTo

internal data class ComposePrefill(
    val to: String,
    val subject: String,
    val bodyHtml: String,
)

internal fun Intent.isExternalComposeIntent(): Boolean =
    action == Intent.ACTION_SENDTO || action == Intent.ACTION_SEND || action == Intent.ACTION_SEND_MULTIPLE

/** Normalizes Android's public compose intents before any value reaches the editor. */
internal fun parseComposeIntent(intent: Intent, plainTextToHtml: (String) -> String): ComposePrefill {
    if (intent.action == Intent.ACTION_SENDTO && intent.data?.scheme.equals("mailto", ignoreCase = true)) {
        val mailTo = runCatching { MailTo.parse(intent.data.toString()) }.getOrNull()
        return ComposePrefill(
            to = mailTo?.to.orEmpty(),
            subject = mailTo?.subject.orEmpty(),
            bodyHtml = plainTextToHtml(mailTo?.body.orEmpty()),
        )
    }

    val recipients = intent.getStringExtra(ComposeActivity.EXTRA_TO)
        ?: intent.getStringArrayExtra(Intent.EXTRA_EMAIL)?.joinToString(", ")
        ?: ""
    val subject = intent.getStringExtra(ComposeActivity.EXTRA_SUBJECT)
        ?: intent.getStringExtra(Intent.EXTRA_SUBJECT)
        ?: ""
    val bodyHtml = intent.getStringExtra(ComposeActivity.EXTRA_BODY_HTML)
        ?: plainTextToHtml(
            intent.getStringExtra(ComposeActivity.EXTRA_BODY)
                ?: intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                ?: "",
        )
    return ComposePrefill(recipients, subject, bodyHtml)
}
