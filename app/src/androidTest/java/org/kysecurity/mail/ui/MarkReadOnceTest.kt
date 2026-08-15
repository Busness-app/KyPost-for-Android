package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity

@RunWith(AndroidJUnit4::class)
class MarkReadOnceTest {

    @Test
    fun markReadIsNotResubmittedOnRecreate() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(context, EmailDetailActivity::class.java).apply {
            putExtra("email_id", "test-message-1")
            putExtra("email_folder", "INBOX")
        }

        ActivityScenario.launch<EmailDetailActivity>(intent).use { scenario ->
            scenario.onActivity { assertEquals(1, it.markReadSubmitCountForTest()) }
            scenario.recreate()
            scenario.onActivity { assertEquals(1, it.markReadSubmitCountForTest()) }
        }
    }
}
