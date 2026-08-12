// app/src/androidTest/java/org/kysecurity/mail/contacts/RepeatableFieldListTest.kt
package org.kysecurity.mail.contacts

import android.view.ContextThemeWrapper
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import androidx.core.widget.doAfterTextChanged
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RepeatableFieldListTest {

    private lateinit var container: LinearLayout
    private lateinit var addButton: Button
    private var changeCount = 0

    @Before
    fun setUp() {
        val context = ContextThemeWrapper(
            InstrumentationRegistry.getInstrumentation().targetContext,
            R.style.Theme_KyPost,
        )
        container = LinearLayout(context)
        addButton = Button(context)
        changeCount = 0
    }

    private fun newList(): RepeatableFieldList<ContactFieldDto> = RepeatableFieldList(
        container = container,
        addButton = addButton,
        rowLayoutRes = R.layout.row_contact_two_field,
        removeButtonId = R.id.rowFieldRemove,
        bind = { rowView, item, onItemChanged ->
            val a = rowView.findViewById<EditText>(R.id.rowFieldA)
            val b = rowView.findViewById<EditText>(R.id.rowFieldB)
            a.setText(item.label.orEmpty())
            b.setText(item.value)
            a.doAfterTextChanged { onItemChanged(item.copy(label = a.text.toString().ifBlank { null })) }
            b.doAfterTextChanged { onItemChanged(item.copy(value = b.text.toString())) }
        },
        isBlank = { it.label.isNullOrBlank() && it.value.isBlank() },
        default = { ContactFieldDto() },
        onChanged = { changeCount++ },
    )

    @Test
    fun setItems_thenItems_roundTripsNonBlankRows() {
        val list = newList()
        list.setItems(listOf(ContactFieldDto(label = "Home", value = "a@example.com")))

        assertEquals(1, container.childCount)
        assertEquals(listOf(ContactFieldDto(label = "Home", value = "a@example.com")), list.items())
    }

    @Test
    fun tappingAddButton_addsABlankRow_droppedByItemsUntilFilled() {
        val list = newList()
        list.setItems(emptyList())

        addButton.performClick()

        assertEquals(1, container.childCount)
        assertTrue("a freshly-added blank row must not appear in items()", list.items().isEmpty())

        val row = container.getChildAt(0)
        row.findViewById<EditText>(R.id.rowFieldB).setText("new@example.com")

        assertEquals(listOf(ContactFieldDto(value = "new@example.com")), list.items())
    }

    @Test
    fun tappingRemove_removesExactlyThatRow_evenAfterEarlierRemovals() {
        val list = newList()
        list.setItems(
            listOf(
                ContactFieldDto(label = "First", value = "1@example.com"),
                ContactFieldDto(label = "Second", value = "2@example.com"),
                ContactFieldDto(label = "Third", value = "3@example.com"),
            ),
        )

        container.getChildAt(0).findViewById<android.view.View>(R.id.rowFieldRemove).performClick()
        assertEquals(2, container.childCount)

        // Removing the (now first) row again must remove "Second", not stale-index into "Third".
        container.getChildAt(0).findViewById<android.view.View>(R.id.rowFieldRemove).performClick()

        assertEquals(listOf(ContactFieldDto(label = "Third", value = "3@example.com")), list.items())
    }

    @Test
    fun everyMutation_firesOnChanged() {
        val list = newList()
        list.setItems(listOf(ContactFieldDto(value = "a@example.com")))
        val afterSetItems = changeCount
        assertTrue(afterSetItems > 0)

        addButton.performClick()
        assertTrue(changeCount > afterSetItems)
    }
}
