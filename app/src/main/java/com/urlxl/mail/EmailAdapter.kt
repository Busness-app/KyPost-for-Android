package com.urlxl.mail

import android.graphics.Color
import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.RecyclerView
import com.urlxl.mail.pgp.PgpMessageState
import com.urlxl.mail.pgp.pgpMessageStateOf
import com.urlxl.mail.pgp.pgpRowMarker

class EmailAdapter(
    private var emails: List<Email>,
    private val onEmailClick: ((Email) -> Unit)? = null
) : RecyclerView.Adapter<EmailAdapter.EmailViewHolder>() {

    class EmailViewHolder(view: View, private val onEmailClick: ((Email) -> Unit)?) : RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val contentLayout: LinearLayout = view.findViewById(R.id.emailItemContent)
        private val unreadDot: View = view.findViewById(R.id.unreadDot)
        private val subjectTextView: TextView = view.findViewById(R.id.textViewSubject)
        private val senderTextView: TextView = view.findViewById(R.id.textViewSender)

        fun bind(email: Email, palette: ThemePalette) {
            // A message this app can't render is worth knowing before tapping it — otherwise the
            // only signal is opening it and finding nothing there.
            val pgpState = pgpMessageStateOf(email.pgpEncrypted, email.pgpDecryptError, email.body)
            val markers = listOfNotNull(pgpRowMarker(pgpState), if (email.hasAttachments) "📎" else null)
            subjectTextView.text = (markers + email.subject).joinToString(" ")
            // The markers are emoji, which screen readers announce inconsistently or not at all,
            // so spell the state out instead of relying on them being read.
            subjectTextView.contentDescription = when (pgpState) {
                PgpMessageState.CLIENT_PROTECTED ->
                    itemView.context.getString(R.string.email_row_pgp_locked_description, email.subject)
                PgpMessageState.DECRYPT_FAILED ->
                    itemView.context.getString(R.string.email_row_pgp_failed_description, email.subject)
                else -> null
            }
            senderTextView.text = email.sender

            val panel = Color.parseColor(palette.panel)
            cardView.setCardBackgroundColor(panel)
            contentLayout.setBackgroundColor(panel)

            // Minor "unread" cue: a small accent dot plus a bolder, higher-contrast subject —
            // the same signal used for keyword pills with unread mail (InboxActivity.styleKeywordChip).
            val isUnread = email.status == "unread"
            unreadDot.visibility = if (isUnread) View.VISIBLE else View.GONE
            if (isUnread) {
                unreadDot.background = unreadDotDrawable(itemView.context)
            }
            subjectTextView.setTypeface(subjectTextView.typeface, if (isUnread) Typeface.BOLD else Typeface.NORMAL)
            subjectTextView.setTextColor(Color.parseColor(if (isUnread) palette.inkStrong else palette.ink))
            senderTextView.setTextColor(Color.parseColor(palette.ink))

            itemView.setOnClickListener { onEmailClick?.invoke(email) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EmailViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_email, parent, false)
        return EmailViewHolder(view, onEmailClick)
    }

    override fun onBindViewHolder(holder: EmailViewHolder, position: Int) {
        val palette = getStoredThemePalette(holder.itemView.context)
        holder.bind(emails[position], palette)
    }

    override fun getItemCount(): Int = emails.size

    fun getEmailAt(position: Int): Email = emails[position]

    fun updateEmails(newEmails: List<Email>) {
        emails = newEmails
        notifyDataSetChanged()
    }
}