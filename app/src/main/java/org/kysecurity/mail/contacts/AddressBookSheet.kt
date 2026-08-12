package org.kysecurity.mail.contacts

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import org.kysecurity.mail.R
import org.kysecurity.mail.data.DataRuntime
import kotlinx.coroutines.launch

/** Address-book picker (ContactAutocomplete.md section 3): search bar + scrollable contact list
 *  with TO/CC/BCC action chips per row. Stays open across picks so the user can multi-select —
 *  [onPick] fires once per successful pick; see [RecipientRowAdapter] for the checkmark state. */
class AddressBookSheet @JvmOverloads constructor(
    private val onPick: ((RecipientCandidate, RecipientField) -> Boolean)? = null,
) : BottomSheetDialogFragment() {

    private lateinit var adapter: RecipientRowAdapter
    private lateinit var emptyText: View
    private val handler = Handler(Looper.getMainLooper())
    private var pendingSearch: Runnable? = null
    private var allCandidates: List<RecipientCandidate> = emptyList()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        inflater.inflate(R.layout.sheet_address_book, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val onPick = onPick ?: run {
            dismiss()
            return
        }
        val searchField = view.findViewById<EditText>(R.id.addressBookSearchField)
        val recyclerView = view.findViewById<RecyclerView>(R.id.addressBookRecyclerView)
        emptyText = view.findViewById(R.id.addressBookEmptyText)

        adapter = RecipientRowAdapter(onPick = onPick)
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter

        searchField.doAfterTextChanged { text ->
            pendingSearch?.let(handler::removeCallbacks)
            val query = text?.toString().orEmpty()
            val runnable = Runnable { render(filter(query)) }
            pendingSearch = runnable
            handler.postDelayed(runnable, DEBOUNCE_MS)
        }

        val contactDao = DataRuntime.graph(requireContext()).database.contactDao()
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                contactDao.observeAll().collect { contacts ->
                    allCandidates = contacts.mapNotNull { it.toRecipientCandidateOrNull() }
                    render(filter(searchField.text?.toString().orEmpty()))
                }
            }
        }
    }

    private fun filter(query: String): List<RecipientCandidate> = if (query.isBlank()) {
        allCandidates
    } else {
        allCandidates.filter { it.name.contains(query, ignoreCase = true) || it.email.contains(query, ignoreCase = true) }
    }

    private fun render(list: List<RecipientCandidate>) {
        adapter.submitList(list)
        emptyText.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        pendingSearch?.let(handler::removeCallbacks)
    }

    companion object {
        const val TAG = "AddressBookSheet"
        private const val DEBOUNCE_MS = 150L
    }
}
