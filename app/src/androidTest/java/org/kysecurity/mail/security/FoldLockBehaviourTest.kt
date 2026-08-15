package org.kysecurity.mail.security

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity

/**
 * The two halves of the foldable lock contract. A live resize must not lock; a close-and-lock must.
 * Neither is assumed anywhere in this feature — both are asserted here.
 */
@RunWith(AndroidJUnit4::class)
class FoldLockBehaviourTest {

    private val appLockManager
        get() = SecurityRuntime.graph(
            InstrumentationRegistry.getInstrumentation().targetContext,
        ).appLockManager

    @Test
    fun aLiveResizeDoesNotEngageTheAppLock() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.recreate()

            assertFalse(
                "A configuration-change recreate must not lock the app — every unfold would prompt for a PIN.",
                appLockManager.isLockedNow(),
            )
        }
    }

    @Test
    fun lockNowStillGatesTheInbox() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            appLockManager.lockNow()

            scenario.recreate()

            scenario.onActivity { activity ->
                assertTrue(
                    "A locked app must finish a gated screen rather than leave it under the prompt.",
                    activity.isFinishing || activity.isDestroyed,
                )
            }
        }
    }
}
