package org.kysecurity.mail.security

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.os.Bundle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity

/**
 * The three halves of the foldable lock contract. A live resize must not lock; a close-and-lock
 * must; and, unique to this feature, two embedded panes locking at once must still collapse into
 * one unlock prompt. None is assumed anywhere in this feature — all three are asserted here.
 *
 * None of these have run in this environment — see the spec's "Verification results" section.
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

    /**
     * Before Activity Embedding, two [LockedActivity] instances could never be visible at once —
     * this test's whole premise is a code path that has never existed in this app until this
     * feature. [InboxActivity] as the primary pane and [EmailDetailActivity] as the secondary
     * stand in for a split; locking both, independently, each redirects to [UnlockActivity] and
     * `finish()`es itself ([LockedActivity.redirectToUnlockIfLocked]). [UnlockActivity] is
     * `android:launchMode="singleInstance"` (`AndroidManifest.xml`, around `:171`), so the second
     * `startActivity` call is contractually required to resolve against the instance the first
     * call created rather than starting a new one — that collapse, not merely "both panes gate",
     * is the property this test exists for.
     *
     * [ActivityLifecycleCallbacks] observes `onActivityCreated` process-wide, which is the one
     * signal that distinguishes "the second call was routed to the existing singleInstance" from
     * "the second call created a stacked second prompt": `singleInstance` delivery to an existing
     * instance is [Activity.onNewIntent], not a fresh `onCreate`. This is a direct assertion of the
     * launch-mode contract, not a proxy for it — what it cannot show, without a real device to
     * render to, is that no pane is visible *behind* the one instance; `isFinishing`/`isDestroyed`
     * on both source Activities is the closest approximation available off-device, exactly as in
     * [lockNowStillGatesTheInbox] above.
     */
    @Test
    fun lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext
            .applicationContext as Application
        val unlockActivityCreations = AtomicInteger(0)
        val callbacks = object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                if (activity is UnlockActivity) unlockActivityCreations.incrementAndGet()
            }
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityResumed(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        }
        app.registerActivityLifecycleCallbacks(callbacks)
        try {
            val detailIntent = Intent(
                InstrumentationRegistry.getInstrumentation().targetContext,
                EmailDetailActivity::class.java,
            ).apply {
                putExtra("email_id", "test-message-1")
                putExtra("email_folder", "INBOX")
            }

            ActivityScenario.launch(InboxActivity::class.java).use { primary ->
                ActivityScenario.launch<EmailDetailActivity>(detailIntent).use { secondary ->
                    appLockManager.lockNow()

                    primary.recreate()
                    secondary.recreate()

                    primary.onActivity { activity ->
                        assertTrue(
                            "The primary pane must not survive a lock underneath its own prompt.",
                            activity.isFinishing || activity.isDestroyed,
                        )
                    }
                    secondary.onActivity { activity ->
                        assertTrue(
                            "The secondary pane must not survive a lock underneath its own prompt.",
                            activity.isFinishing || activity.isDestroyed,
                        )
                    }

                    assertEquals(
                        "Two embedded panes locking at once must collapse into ONE unlock " +
                            "prompt via UnlockActivity's singleInstance launch mode, not stack two.",
                        1,
                        unlockActivityCreations.get(),
                    )
                }
            }
        } finally {
            app.unregisterActivityLifecycleCallbacks(callbacks)
        }
    }
}
