package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity

/**
 * A live resize (unfolding while the app is in the foreground) is a configuration change, so the
 * Activity is destroyed and recreated. recreate() reproduces exactly that path.
 */
@RunWith(AndroidJUnit4::class)
class InboxStateRestoreTest {

    @Test
    fun folderAndTabSurviveRecreate() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { it.setFolderForTest("Archive", "Finance") }

            scenario.recreate()

            scenario.onActivity {
                assertEquals("Archive", it.currentFolderForTest())
                assertEquals("Finance", it.selectedTabForTest())
            }
        }
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
