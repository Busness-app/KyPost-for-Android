package org.kysecurity.mail

import android.content.Context
import android.graphics.Typeface
import android.text.SpannableString
import android.text.style.StyleSpan
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.AutoCompleteTextView
import android.widget.BaseAdapter
import android.widget.Filter
import android.widget.Filterable
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.contacts.RecipientCandidate
import org.kysecurity.mail.contacts.isDuplicateRecipient
import org.kysecurity.mail.contacts.isValidEmailFormat
import org.kysecurity.mail.contacts.matchRanges
import androidx.lifecycle.findViewTreeLifecycleOwner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * One TO/CC/BCC recipient field: an [AutoCompleteTextView] backed by a local-contact [Filter],
 * plus a [ChipGroup] of already-added recipient pills. ComposeActivity creates three instances.
 * Implements ContactAutocomplete.md sections 1, 2, and the "invalid formats"/"duplicate
 * prevention" parts of section 4 (the address-book modal itself is [org.kysecurity.mail.contacts.AddressBookSheet]).
 */
class RecipientInputView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    private val labelView: TextView
    private val field: AutoCompleteTextView
    private val bookButton: View
    private val chipGroup: ChipGroup
    private val recipients = mutableListOf<String>()

    /** Fires after a recipient is actually added or removed — i.e. once per committed change to
     *  [recipientEmails], never per keystroke. ComposeActivity uses this to re-run the encrypt
     *  preflight when the committed address set changes while Encrypt is checked. */
    var onRecipientsChanged: (() -> Unit)? = null

    /** The in-flight suggestion lookup, cancelled by the next keystroke. See [debounceAndSearch]. */
    private var searchJob: kotlinx.coroutines.Job? = null

    init {
        orientation = VERTICAL
        LayoutInflater.from(context).inflate(R.layout.view_recipient_input, this, true)
        labelView = findViewById(R.id.recipientInputLabel)
        field = findViewById(R.id.recipientInputField)
        bookButton = findViewById(R.id.recipientInputBookButton)
        chipGroup = findViewById(R.id.recipientInputChips)

        field.setOnItemClickListener { _, _, position, _ ->
            (field.adapter as? SuggestionAdapter)?.getCandidateAt(position)?.let {
                addRecipient(it.email, it.name)
            }
        }
        field.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                commitTypedEmail()
                true
            } else {
                false
            }
        }
        field.doAfterTextChanged { text ->
            if (text != null && (text.endsWith(",") || text.endsWith(" "))) {
                commitTypedEmail()
            }
        }
    }

    fun setLabel(text: CharSequence) {
        labelView.text = text
    }

    /** Wires local-contact search into the dropdown. Pass [onOpenAddressBook] on exactly one of
     *  the three TO/CC/BCC instances (ComposeActivity uses the TO row) — the address-book modal
     *  itself offers TO/CC/BCC actions per contact, so a single entry point covers all three
     *  fields; showing the icon on every field would just be three doors to the same room. */
    fun configure(search: suspend (String) -> List<RecipientCandidate>, onOpenAddressBook: (() -> Unit)? = null) {
        val adapter = SuggestionAdapter(context)
        field.setAdapter(adapter)
        field.doAfterTextChanged { editable -> debounceAndSearch(adapter, search, editable?.toString().orEmpty()) }
        if (onOpenAddressBook != null) {
            bookButton.visibility = View.VISIBLE
            bookButton.setOnClickListener { onOpenAddressBook() }
        }
    }

    /** Parses a comma-separated address string (matches [org.kysecurity.mail.mail.MailDraft]'s wire
     *  shape) into chips — used to prefill from ComposeActivity.EXTRA_TO on reply/forward. */
    fun setInitialRecipients(commaSeparated: String) {
        commaSeparated.split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .forEach { addRecipient(it) }
    }

    /** Adds [email] as a chip if it isn't already present in this field. Returns false (and shows
     *  a duplicate toast) otherwise — [org.kysecurity.mail.contacts.AddressBookSheet] uses the return
     *  value to decide whether to flip its per-row checkmark. */
    fun addRecipient(email: String, displayName: String? = null): Boolean {
        if (isDuplicateRecipient(recipients, email)) {
            Toast.makeText(context, context.getString(R.string.recipient_duplicate_toast, email), Toast.LENGTH_SHORT).show()
            return false
        }
        recipients.add(email)
        val chip = Chip(context).apply {
            text = displayName?.takeIf { it.isNotBlank() } ?: email
            isCloseIconVisible = true
            setOnCloseIconClickListener {
                recipients.remove(email)
                chipGroup.removeView(this)
                chipGroup.visibility = if (chipGroup.childCount == 0) View.GONE else View.VISIBLE
                onRecipientsChanged?.invoke()
            }
        }
        applyPillChipTheme(context, chip)
        chipGroup.addView(chip)
        chipGroup.visibility = View.VISIBLE
        field.setText("")
        field.dismissDropDown()
        onRecipientsChanged?.invoke()
        return true
    }

    fun recipientEmails(): List<String> = recipients.toList()

    /** Matches [org.kysecurity.mail.mail.MailDraft]'s to/cc/bcc wire shape. */
    fun commaJoinedRecipients(): String = recipients.joinToString(",")

    /** Re-tints existing chips after a theme switch — call from the host Activity's onResume,
     *  alongside its other applyXTheme() calls. */
    fun applyTheme() {
        for (i in 0 until chipGroup.childCount) {
            (chipGroup.getChildAt(i) as? Chip)?.let { applyPillChipTheme(context, it) }
        }
    }

    private fun commitTypedEmail() {
        val typed = field.text.toString().trim(' ', ',')
        if (typed.isBlank()) return
        if (!isValidEmailFormat(typed)) {
            Toast.makeText(context, R.string.recipient_invalid_email_toast, Toast.LENGTH_SHORT).show()
            return
        }
        addRecipient(typed)
    }

    /**
     * Dropdown adapter. **No [Filterable], and no [Filter].**
     *
     * [debounceAndSearch] does it in the coroutine world instead, where cancelling the previous
     * job actually cancels it and the query never runs at all.
     */
    private inner class SuggestionAdapter(
        context: Context,
    ) : BaseAdapter(), Filterable {

        private var results: List<RecipientCandidate> = emptyList()
        private var lastQuery: String = ""
        private val inflater = LayoutInflater.from(context)

        fun getCandidateAt(position: Int): RecipientCandidate? = results.getOrNull(position)

        override fun getCount(): Int = if (results.isEmpty() && lastQuery.isNotBlank()) 1 else results.size

        override fun getItem(position: Int): Any? = results.getOrNull(position)

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val view = convertView ?: inflater.inflate(R.layout.item_recipient_suggestion, parent, false)
            val nameView = view.findViewById<TextView>(R.id.recipientSuggestionName)
            val emailView = view.findViewById<TextView>(R.id.recipientSuggestionEmail)
            val candidate = results.getOrNull(position)
            if (candidate == null) {
                nameView.text = context.getString(R.string.recipient_no_contacts_found)
                emailView.text = ""
            } else {
                nameView.text = bolded(candidate.name, lastQuery)
                emailView.text = bolded(candidate.email, lastQuery)
            }
            return view
        }

        private fun bolded(text: String, query: String): CharSequence {
            val span = SpannableString(text)
            matchRanges(text, query).forEach { range ->
                span.setSpan(StyleSpan(Typeface.BOLD), range.first, range.last + 1, SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            return span
        }

        /** Called on the main thread once a debounced search has actually completed. */
        fun submit(query: String, matches: List<RecipientCandidate>) {
            lastQuery = query
            results = matches
            notifyDataSetChanged()
        }

        /**
         * [AutoCompleteTextView.setAdapter] requires a [Filterable], so one is provided — but it
         * does no work.
         *
         * All this does is hand back whatever [submit] last published, so the dropdown can size
         * itself. The searching happens in [debounceAndSearch], on a cancellable coroutine, because
         * `Filter`'s single serialised worker thread is the wrong place for a debounce and the
         * worst place for a blocking database call.
         */
        override fun getFilter(): Filter = object : Filter() {
            override fun performFiltering(constraint: CharSequence?): FilterResults =
                FilterResults().apply {
                    values = results
                    count = this@SuggestionAdapter.count
                }

            override fun publishResults(constraint: CharSequence?, filterResults: FilterResults?) {
                notifyDataSetChanged()
            }
        }
    }

    /**
     * A real debounce: the pending job is cancelled outright by the next keystroke, so a superseded
     * query never reaches the database.
     *
     * Scoped to the view's lifecycle via [findViewTreeLifecycleOwner], so a search in flight when
     * the screen goes away is cancelled with it rather than resuming against a closed database —
     * which the old `runBlocking` on a `Filter` thread had no way to avoid.
     */
    private fun debounceAndSearch(
        adapter: SuggestionAdapter,
        search: suspend (String) -> List<RecipientCandidate>,
        query: String,
    ) {
        searchJob?.cancel()
        val scope = findViewTreeLifecycleOwner()?.lifecycleScope ?: return
        searchJob = scope.launch {
            delay(DEBOUNCE_MS)
            val matches = if (query.isBlank()) emptyList() else search(query).take(MAX_RESULTS)
            // Still the current text? The delay above already drops most stale queries; this covers
            // a search slower than the next keystroke.
            if (field.text.toString() != query) return@launch
            adapter.submit(query, matches)
            if (matches.isNotEmpty() || query.isNotBlank()) field.showDropDown()
        }
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        searchJob?.cancel()
        searchJob = null
    }

    private companion object {
        const val DEBOUNCE_MS = 150L
        const val MAX_RESULTS = 5
    }
}
