package org.kysecurity.mail.push

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the user is told when UnifiedPush stops working.
 *
 *  The message used to be a fixed "— reverted to Firebase". On the F-Droid build there is no
 *  Firebase to revert to, so that sentence is simply false, and it is false in the worst
 *  direction: it tells a user whose notifications have just stopped that delivery was restored. */
class UnifiedPushFailureReportTest {

    @Test
    fun aBuildWithASecondTransportSaysItRevertedToIt() {
        val message = unifiedPushFailureMessage(reason = "NETWORK", canFallBack = true)

        assertTrue(message, message.contains("NETWORK"))
        assertTrue("should name the fallback: $message", message.contains("Firebase", ignoreCase = true))
    }

    @Test
    fun aBuildWithNoSecondTransportDoesNotClaimToHaveRevertedAnywhere() {
        val message = unifiedPushFailureMessage(reason = "NETWORK", canFallBack = false)

        assertTrue(message, message.contains("NETWORK"))
        assertFalse(
            "A Firebase-free build must not claim it reverted to Firebase: $message",
            message.contains("Firebase", ignoreCase = true),
        )
        assertFalse(
            "\"reverted\" implies delivery was restored, and nothing was: $message",
            message.contains("revert", ignoreCase = true),
        )
    }

    /** The message is shown on the pairing screen, so it has to say what the user can do rather
     *  than only what failed. */
    @Test
    fun theNoFallbackMessagePointsAtTheDistributor() {
        val message = unifiedPushFailureMessage(reason = "NETWORK", canFallBack = false)

        assertTrue("should mention the distributor: $message", message.contains("distributor", ignoreCase = true))
    }
}
