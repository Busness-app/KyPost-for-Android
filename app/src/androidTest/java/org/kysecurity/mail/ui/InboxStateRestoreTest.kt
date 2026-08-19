package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordSettings

/**
 * A live resize (unfolding while the app is in the foreground) is a configuration change, so the
 * Activity is destroyed and recreated. recreate() reproduces exactly that path.
 */
@RunWith(AndroidJUnit4::class)
class InboxStateRestoreTest {

    private val keywordSettings =
        KeywordSettings(InstrumentationRegistry.getInstrumentation().targetContext)

    /** rebuildTabs builds chips from KeywordSettings, so the tab's keyword must be registered. */
    @Before
    fun rememberTheKeywordTheTabNames() {
        keywordSettings.rememberKeywords(setOf(TAB_KEYWORD))
        // Set visibility explicitly rather than relying on the default: [forgetTheKeyword] hides it
        // afterwards, and JUnit does not promise method order, so a later method in this class must
        // not inherit the hidden state from an earlier one and lose the chip.
        keywordSettings.setKeywordVisible(TAB_KEYWORD, true)
    }

    /** KeywordSettings has no removal API, so hide it to keep it out of later test classes. */
    @After
    fun forgetTheKeyword() {
        keywordSettings.setKeywordVisible(TAB_KEYWORD, false)
    }

    @Test
    fun folderAndTabSurviveRecreate() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { it.setFolderForTest("Archive", TAB_KEYWORD) }

            scenario.recreate()

            scenario.onActivity {
                assertEquals("Archive", it.currentFolderForTest())
                assertEquals(TAB_KEYWORD, it.selectedTabForTest())
            }
        }
    }

    private companion object {
        const val TAB_KEYWORD = "Finance"
    }

    /** The adapter is still empty after recreate; the saved scroll target must survive that render. */
    @Test
    fun pendingScrollPositionIsNotConsumedByAnEmptyRenderAfterRecreate() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.recreate()

            scenario.onActivity { it.setPendingScrollPositionForTest(50) }

            // Drop out of and back into RESUMED without a destroy/recreate: this re-runs
            // onResume()'s renderFilteredEmails() call on the same instance, against the still-
            // empty adapter, which is the exact render the fix guards.
            scenario.moveToState(Lifecycle.State.STARTED)
            scenario.moveToState(Lifecycle.State.RESUMED)

            scenario.onActivity {
                assertEquals(50, it.pendingScrollPositionForTest())
            }
        }
    }
}
