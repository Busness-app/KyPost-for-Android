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

    /**
     * The restored tab only survives if a chip for it still exists after the recreate, and
     * `rebuildTabs` builds those chips from [KeywordSettings], not from the current email batch
     * (`InboxActivity.kt:470-481`). A tab naming a keyword the app has never seen is correctly
     * reset to All — so a test that sets one through a seam without registering it is asserting a
     * promise production does not make, and it fails for that reason rather than a broken restore.
     *
     * On a real device the keyword is already remembered, because the only way to select the chip
     * is for the chip to exist. Registering it here reproduces that precondition instead of
     * weakening the assertion.
     */
    @Before
    fun rememberTheKeywordTheTabNames() {
        keywordSettings.rememberKeywords(setOf(TAB_KEYWORD))
        // Set visibility explicitly rather than relying on the default: [forgetTheKeyword] hides it
        // afterwards, and JUnit does not promise method order, so a later method in this class must
        // not inherit the hidden state from an earlier one and lose the chip.
        keywordSettings.setKeywordVisible(TAB_KEYWORD, true)
    }

    /**
     * Keyword storage is SharedPreferences-backed and process-wide, and [KeywordSettings] exposes
     * no removal API — so hiding is the supported way to stop an invented keyword becoming a chip
     * in every later test class. `rebuildTabs` builds its chips from `filterVisible`, so a hidden
     * keyword contributes nothing.
     */
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

    /**
     * `refreshInbox()`'s async fetch has not populated the adapter yet when `onResume()` runs
     * `renderFilteredEmails()` right after a recreate, so the list is empty at that moment. A
     * saved scroll target must survive that empty render, or it is lost before the data (and the
     * position it was meant to restore) ever arrives. This environment has no network/cache data,
     * so the adapter is guaranteed empty here -- reproducing exactly that window without needing a
     * populated list.
     */
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
