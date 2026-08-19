package org.kysecurity.mail.contacts

import android.view.ContextThemeWrapper
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExpandableSectionViewTest {

    // Header needs ?attr/selectableItemBackground; the bare targetContext theme can't resolve it.
    private val context = ContextThemeWrapper(
        InstrumentationRegistry.getInstrumentation().targetContext,
        R.style.Theme_KyPost,
    )

    @Test
    fun startsCollapsed_bodyGoneUntilExpanded() {
        val section = ExpandableSectionView(context, null)

        assertFalse(section.isExpanded)
        assertEquals(View.GONE, section.body.visibility)

        section.setExpanded(true)

        assertTrue(section.isExpanded)
        assertEquals(View.VISIBLE, section.body.visibility)
    }

    @Test
    fun tappingHeader_togglesExpansion() {
        val section = ExpandableSectionView(context, null)
        val header = section.getChildAt(0)

        header.performClick()
        assertTrue(section.isExpanded)

        header.performClick()
        assertFalse(section.isExpanded)
    }

    @Test
    fun programmaticallyAddedChild_landsInBody_viaOnFinishInflate() {
        val section = ExpandableSectionView(context, null)
        val staticField = EditText(context)
        section.addView(staticField)

        // onFinishInflate only runs for XML-inflated views; call it directly to simulate that path
        // for a view constructed programmatically in this unit test.
        section.onFinishInflateForTest()

        assertEquals(0, (section as LinearLayout).let { (2 until it.childCount).count() })
        assertTrue(section.body.indexOfChild(staticField) >= 0)
    }
}
