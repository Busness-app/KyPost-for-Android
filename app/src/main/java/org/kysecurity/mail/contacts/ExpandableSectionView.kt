package org.kysecurity.mail.contacts

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import org.kysecurity.mail.R

// Children declared in XML inside this tag are moved into [body] by [onFinishInflate].
class ExpandableSectionView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : LinearLayout(context, attrs) {

    val body: LinearLayout = LinearLayout(context).apply {
        orientation = VERTICAL
        visibility = GONE
    }

    private val headerTitle: TextView
    private val headerCount: TextView
    private val headerChevron: TextView

    var isExpanded: Boolean = false
        private set

    init {
        orientation = VERTICAL
        val header = LayoutInflater.from(context).inflate(R.layout.view_expandable_section_header, this, false)
        headerTitle = header.findViewById(R.id.sectionHeaderTitle)
        headerCount = header.findViewById(R.id.sectionHeaderCount)
        headerChevron = header.findViewById(R.id.sectionHeaderChevron)
        header.setOnClickListener { setExpanded(!isExpanded) }
        addView(header)
        addView(body)
        setExpanded(false)
    }

    override fun onFinishInflate() {
        super.onFinishInflate()
        // Index 0 is the header, index 1 is body, both added in init above. Anything declared in
        // XML inside this tag lands after them and belongs in body instead.
        if (childCount > 2) {
            val staticChildren = (2 until childCount).map { getChildAt(it) as View }
            staticChildren.forEach { removeView(it) }
            staticChildren.forEach { body.addView(it) }
        }
    }

    fun setTitle(title: String) {
        headerTitle.text = title
    }

    fun setItemCount(count: Int) {
        headerCount.visibility = if (count > 0) VISIBLE else GONE
        headerCount.text = java.text.NumberFormat.getIntegerInstance().format(count)
    }

    fun setExpanded(expanded: Boolean) {
        isExpanded = expanded
        body.visibility = if (expanded) VISIBLE else GONE
        headerChevron.text = if (expanded) "▾" else "▸"
    }

    /** Test-only: [onFinishInflate] is protected and only the inflater ever calls it. */
    internal fun onFinishInflateForTest() = onFinishInflate()
}
