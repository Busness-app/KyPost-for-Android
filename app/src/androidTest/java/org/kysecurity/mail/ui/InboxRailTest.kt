package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.navigationrail.NavigationRailView
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.R

/** nav_is_rail and the layout share a qualifier, so this passes on both phone and tablet. */
@RunWith(AndroidJUnit4::class)
class InboxRailTest {

    @Test
    fun navWidgetMatchesTheBoolResource() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expectRail = context.resources.getBoolean(R.bool.nav_is_rail)

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val nav = activity.findViewById<NavigationBarView>(R.id.bottomNavigation)
                assertEquals(expectRail, nav is NavigationRailView)
                assertEquals(5, nav.menu.size())
                assertEquals(context.getString(R.string.nav_inbox), nav.menu.findItem(R.id.nav_inbox).title.toString())

                activity.setFolderForTest("Junk", "All")
                assertEquals(context.getString(R.string.nav_junk), nav.menu.findItem(R.id.nav_inbox).title.toString())
            }
        }
    }
}
