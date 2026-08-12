// app/src/androidTest/java/org/kysecurity/mail/contacts/ExpandableSectionViewTest.kt
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

    // The header layout references ?attr/selectableItemBackground (view_expandable_section_header.xml),
    // an AppCompat/MaterialComponents theme attribute. The bare instrumentation targetContext isn't
    // themed (it resolves to the plain framework theme), so it fails to inflate with
    // "Failed to resolve attribute" — wrap it in the app's real theme, exactly like every Activity in
    // this app gets via the manifest's android:theme="@style/Theme.KyPost".
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
