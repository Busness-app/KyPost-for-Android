package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.contacts.ContactEditActivity
import org.kysecurity.mail.contacts.ContactEditDraftCache

@RunWith(AndroidJUnit4::class)
class ContactEditDraftTest {

    /** clear() seals the cache; take() drops the draft and unseals it, which is the pristine state
     *  the next test needs. The uid is irrelevant here — a mismatched take drops the draft too. */
    @After
    fun tearDown() {
        ContactEditDraftCache.clear()
        ContactEditDraftCache.take("")
    }

    @Test
    fun typedNameSurvivesRecreate() {
        ActivityScenario.launch(ContactEditActivity::class.java).use { scenario ->
            scenario.onActivity { it.setNameForTest("Ada Lovelace") }

            scenario.recreate()

            scenario.onActivity { assertEquals("Ada Lovelace", it.nameForTest()) }
        }
    }
}
