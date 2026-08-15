package org.kysecurity.mail.ui

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
}
