package org.kysecurity.mail.contacts

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button

// Rows resolve their index via container.indexOfChild at event time, never captured at add-time.
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
