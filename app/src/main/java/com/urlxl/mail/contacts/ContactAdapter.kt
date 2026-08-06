package com.urlxl.mail.contacts

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.RecyclerView
import android.widget.TextView
import com.google.android.material.chip.Chip
import com.urlxl.mail.R
import com.urlxl.mail.ThemePalette
import com.urlxl.mail.applyStatusBadgeTheme
import com.urlxl.mail.bindAvatar
import com.urlxl.mail.data.ContactEntity
import com.urlxl.mail.getStoredThemePalette

class ContactAdapter(
    private var contacts: List<ContactEntity> = emptyList(),
    private val onContactClick: (ContactEntity) -> Unit,
) : RecyclerView.Adapter<ContactAdapter.ContactViewHolder>() {

    /** Whether the paired account has a PGP identity on the server (see [com.urlxl.mail.pgp.hasPgpIdentity]),
     *  `null` while unknown/unchecked. The self-contact's own `pgpKey` field is a normal,
     *  independently-editable contact field with no connection to the account's real PGP identity
     *  (see that function's doc comment) — this is the account-level signal set from outside,
     *  since computing it needs a network call this per-row [bind] has no coroutine scope for. */
    var selfHasPgpIdentity: Boolean? = null
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    class ContactViewHolder(view: View, private val onContactClick: (ContactEntity) -> Unit) :
        RecyclerView.ViewHolder(view) {
        private val cardView: CardView = view as CardView
        private val avatarView: TextView = view.findViewById(R.id.contactAvatar)
        private val nameView: TextView = view.findViewById(R.id.textViewContactName)
        private val detailView: TextView = view.findViewById(R.id.textViewContactDetail)
        private val statusBadge: Chip = view.findViewById(R.id.contactStatusBadge)

        fun bind(contact: ContactEntity, palette: ThemePalette, selfHasPgpIdentity: Boolean?) {
            nameView.text = contact.fn
            val orgText = contact.org?.takeIf { it.isNotBlank() }
            val selfLabel = if (contact.isSelf) itemView.context.getString(R.string.contact_self_label) else null
            detailView.text = listOfNotNull(selfLabel, orgText).joinToString(" · ")
            detailView.visibility = if (detailView.text.isBlank()) View.GONE else View.VISIBLE
            bindAvatar(itemView.context, avatarView, contact.fn, sizeDp = 34)

            val panel = Color.parseColor(palette.panel)
            cardView.setCardBackgroundColor(panel)
            nameView.setTextColor(Color.parseColor(palette.inkStrong))
            detailView.setTextColor(Color.parseColor(palette.ink))

            val hasKey = contactHasLinkedPgpKey(contact.pgpKey, contact.isSelf, selfHasPgpIdentity)
            statusBadge.setText(
                when {
                    hasKey && contact.pgpKeyNeedsReverification -> R.string.contact_status_key_changed
                    hasKey && contact.identityNeedsReview -> R.string.contact_status_identity_changed
                    hasKey -> R.string.contact_status_secure_key
                    else -> R.string.contact_status_no_key
                },
            )
            applyStatusBadgeTheme(itemView.context, statusBadge, active = hasKey)

            itemView.setOnClickListener { onContactClick(contact) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_contact, parent, false)
        return ContactViewHolder(view, onContactClick)
    }

    override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
        holder.bind(contacts[position], getStoredThemePalette(holder.itemView.context), selfHasPgpIdentity)
    }

    override fun getItemCount(): Int = contacts.size

    fun updateContacts(newContacts: List<ContactEntity>) {
        contacts = newContacts
        notifyDataSetChanged()
    }
}

/** Whether a contact's "PGP" status badge should read as linked: either it has its own [pgpKey]
 *  field set (true for any contact, including self, whose key was actually attached — e.g. via the
 *  PGP QR scan flow), or — for the self-contact specifically ([isSelf]) — the account has a
 *  confirmed server PGP identity per [selfHasPgpIdentity]. `null` (unknown/unchecked) is treated as
 *  "no" here, same as a confirmed false — it only ever adds a second way to show "linked", never a
 *  way to hide the [pgpKey]-based one. Takes primitives rather than a [ContactEntity]/`ContactDto`
 *  directly so both (and [com.urlxl.mail.contacts.ContactDetailActivity]'s own read model) can share
 *  it without a shared base type. */
internal fun contactHasLinkedPgpKey(pgpKey: String?, isSelf: Boolean, selfHasPgpIdentity: Boolean?): Boolean =
    !pgpKey.isNullOrBlank() || (isSelf && selfHasPgpIdentity == true)
