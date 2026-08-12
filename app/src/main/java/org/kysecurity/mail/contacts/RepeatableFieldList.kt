// app/src/main/java/org/kysecurity/mail/contacts/RepeatableFieldList.kt
package org.kysecurity.mail.contacts

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button

/**
 * Manages the "rows + Add button" pattern for one list-typed contact field inside an
 * [ExpandableSectionView]'s body. Each row is inflated from [rowLayoutRes] and wired by [bind];
 * [isBlank] decides which rows [items] drops (e.g. an "+Add" tapped but left empty); [default] is
 * what a fresh row starts as. [onChanged] fires after every add/remove/edit so callers can keep an
 * item-count badge live. Removal and edits look up the row's *current* index via
 * `container.indexOfChild(rowView)` rather than capturing a fixed index at add-time, so earlier
 * rows being removed doesn't corrupt later rows' bookkeeping. Purely a layout primitive — knows
 * nothing about contact fields; every DTO-specific mapping lives in [bind]/[isBlank]/[default].
 */
class RepeatableFieldList<T>(
    private val container: ViewGroup,
    addButton: Button,
    private val rowLayoutRes: Int,
    private val removeButtonId: Int,
    private val bind: (rowView: View, item: T, onItemChanged: (T) -> Unit) -> Unit,
    private val isBlank: (T) -> Boolean,
    private val default: () -> T,
    private val onChanged: () -> Unit = {},
) {
    private val rows = mutableListOf<T>()

    init {
        addButton.setOnClickListener { addRow(default()) }
    }

    fun setItems(items: List<T>) {
        container.removeAllViews()
        rows.clear()
        items.forEach { addRow(it) }
    }

    fun items(): List<T> = rows.filterNot(isBlank)

    private fun addRow(item: T) {
        rows.add(item)
        val rowView = LayoutInflater.from(container.context).inflate(rowLayoutRes, container, false)
        val removeButton = rowView.findViewById<View>(removeButtonId)
        removeButton.setOnClickListener {
            val index = container.indexOfChild(rowView)
            if (index >= 0) {
                rows.removeAt(index)
                container.removeViewAt(index)
                onChanged()
            }
        }
        bind(rowView, item) { updated ->
            val index = container.indexOfChild(rowView)
            if (index >= 0) rows[index] = updated
            onChanged()
        }
        container.addView(rowView)
        onChanged()
    }
}
