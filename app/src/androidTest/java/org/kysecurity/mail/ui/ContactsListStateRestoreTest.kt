package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.contacts.ContactsListActivity

@RunWith(AndroidJUnit4::class)
class ContactsListStateRestoreTest {

    @Test
    fun scrollPositionSurvivesRecreate() {
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { it.setPendingScrollForTest(4) }
            scenario.recreate()
            scenario.onActivity { assertEquals(4, it.pendingScrollForTest()) }
        }
    }
}
