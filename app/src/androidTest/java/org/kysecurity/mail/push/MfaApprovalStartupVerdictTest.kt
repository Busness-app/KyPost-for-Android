package org.kysecurity.mail.push

import android.content.Context
import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.security.SecurityWipe

private const val WIPE_STATE_PREFS = "org.kysecurity.mail.wipe_state"
private const val EXTRA_MARKER = "test_marker"

/**
 * [MfaApprovalActivity] sits outside `LockedActivity`, so it carries its own startup-wipe gate —
 * and that gate returns from `onCreate` WITHOUT `finish()`, because the pending verdict is what it
 * is waiting to hear. The activity therefore starts and resumes normally with no content view set
 * and every `lateinit` view unset.
 *
 * That is the trap: `onStop` unconditionally called `setButtonsEnabled(false)`, which touches
 * `denyButton`, so simply backgrounding a challenge that arrived mid-wipe threw
 * `UninitializedPropertyAccessException` out of a lifecycle callback and took the process with it.
 * `onNewIntent` had the matching problem from the other direction. The fix is the
 * `awaitingStartupVerdict` stand-down flag; this is its guard.
 *
 * No challenge extras are passed on purpose: `onCreate` returns at the gate, well before
 * `adoptChallenge` reads the intent, so a payload here would only imply a dependency that the path
 * under test does not have.
 */
@RunWith(AndroidJUnit4::class)
class MfaApprovalStartupVerdictTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Before
    fun openTheGate() {
        // `blockedByAbandonedWipe` is checked BEFORE the gate and redirects to `MainActivity`, so a
        // marker left by an earlier class would finish this activity and the gate would never be
        // reached — the test would pass without exercising anything.
        context.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).edit().clear().commit()

        // ORDER MATTERS. `KyPostApp` completes the real verdict from an IO coroutine at process
        // start, and reopening before that lands hands it the FRESH deferred to close: the gate is
        // shut again before the activity reads it, `onCreate` falls through to `adoptChallenge`,
        // finds no payload and finishes. Awaiting the app's own verdict first makes this
        // independent of how far process startup happens to have got — without it the result
        // depends on method order, which is how the first draft of this test went green by luck.
        runBlocking { withTimeout(30_000) { SecurityWipe.startupVerdict.await() } }
        SecurityWipe.reopenStartupVerdictForTest()
    }

    /**
     * The gate is process-wide. Left open, every later screen in this suite would sit waiting on a
     * verdict that is never delivered, so it is closed again the way `KyPostApp` closes it: a null
     * verdict, meaning no wipe happened.
     */
    @After
    fun closeTheGate() {
        if (!SecurityWipe.startupVerdict.isCompleted) SecurityWipe.startupVerdict.complete(null)
    }

    private fun challengeIntent(marker: String) =
        Intent(context, MfaApprovalActivity::class.java).putExtra(EXTRA_MARKER, marker)

    @Test
    fun stoppingWhileTheStartupVerdictIsPendingDoesNotTouchUnsetViews() {
        ActivityScenario.launch<MfaApprovalActivity>(challengeIntent("first")).use { scenario ->
            // Reaching RESUMED at all is half the assertion: it proves the gate returned without
            // finishing, which is what leaves the unset views reachable from a lifecycle callback.
            assertEquals(Lifecycle.State.RESUMED, scenario.state)

            // onPause + onStop. Before the stand-down flag this threw out of onStop.
            scenario.moveToState(Lifecycle.State.CREATED)
            assertEquals(Lifecycle.State.CREATED, scenario.state)

            // And back up through onStart, which must not raise a PIN prompt mid-wipe either.
            scenario.moveToState(Lifecycle.State.RESUMED)
            assertEquals(Lifecycle.State.RESUMED, scenario.state)
        }
    }

    /**
     * The screen is `singleTop` and the MFA notification targets it directly, so a second challenge
     * arriving while the first still waits on the verdict lands in `onNewIntent`. Delivered through
     * `Instrumentation` rather than by launching again, because the callback — not the task
     * routing — is what carries the guard.
     *
     * Without the stand-down flag this ran on into `adoptChallenge`, which finishes the screen the
     * pending `recreate()` was about to use. The intent must still be adopted, since that recreate
     * is what will render it.
     */
    @Test
    fun aSecondChallengeArrivingWhileTheVerdictIsPendingIsHeldForTheRecreate() {
        ActivityScenario.launch<MfaApprovalActivity>(challengeIntent("first")).use { scenario ->
            assertEquals(Lifecycle.State.RESUMED, scenario.state)

            scenario.onActivity { activity ->
                InstrumentationRegistry.getInstrumentation()
                    .callActivityOnNewIntent(activity, challengeIntent("second"))
            }

            assertEquals(Lifecycle.State.RESUMED, scenario.state)
            scenario.onActivity { activity ->
                assertEquals(
                    "the waiting screen must adopt the new intent for its recreate",
                    "second",
                    activity.intent.getStringExtra(EXTRA_MARKER),
                )
            }
        }
    }
}
