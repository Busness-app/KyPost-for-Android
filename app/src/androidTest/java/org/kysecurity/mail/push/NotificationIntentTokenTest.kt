package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * MainActivity is exported, so every extra on an inbound Intent is reachable by any co-installed
 * app with no permissions at all. This is what tells one of its own PendingIntents apart from a
 * forgery.
 */
@RunWith(AndroidJUnit4::class)
class NotificationIntentTokenTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun theTokenIsStable_soPendingIntentsSurviveAColdStart() {
        val first = NotificationIntentToken.current(context)
        assertEquals(first, NotificationIntentToken.current(context))
        assertTrue(NotificationIntentToken.matches(context, first))
    }

    @Test
    fun anAbsentOrWrongTokenIsRefused() {
        NotificationIntentToken.current(context)
        assertFalse(NotificationIntentToken.matches(context, null))
        assertFalse(NotificationIntentToken.matches(context, ""))
        assertFalse(NotificationIntentToken.matches(context, "not-the-token"))
    }

    /** A guessable token is no token. 32 random bytes, base64. */
    @Test
    fun theTokenIsNotTrivial() {
        val token = NotificationIntentToken.current(context)
        assertTrue("token length ${token.length}", token.length >= 40)
    }
}
