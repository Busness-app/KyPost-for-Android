package org.kysecurity.mail.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

private const val WIPE_STATE_PREFS = "org.kysecurity.mail.wipe_state"

/**
 * Two entry points reach a wipe — [SecurityWipe.enforceTripwire] at startup and the failed-attempt
 * threshold in [AppLockManager] — and the screens that raise the second (UnlockActivity,
 * MfaApprovalActivity) sit outside [LockedActivity]'s startup gate, so they can overlap.
 *
 * Unserialised, the two raced each other's `deleteSharedPreferences`: the loser is told a file it
 * asked to delete could not be deleted, because the winner already had, and that becomes a failed
 * step. A clean wipe then reports as INCOMPLETE — and burns two of three resumes doing it, which
 * is a third of the budget before [LockedActivity] blocks the app permanently.
 */
@RunWith(AndroidJUnit4::class)
class ConcurrentWipeTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    /**
     * The steps whose failure would be CAUSED by two wipes overlapping: each enumerates or deletes
     * shared state and reports "could not delete" for a file another run already removed.
     *
     * Deliberately not "no step may fail". `webViewState` deletes the WebView profile directory,
     * which any earlier test in this process may still hold open — an environmental condition that
     * has nothing to do with serialisation, and asserting on it would make this suite report the
     * emulator's state instead of the mutex's behaviour.
     */
    private val raceSensitiveSteps =
        setOf("sharedPrefs", "datastores", "unifiedPushPrefs", "androidxMasterKey", "database")

    @Before
    fun resetWipeState() {
        context.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun attempts(): Int =
        context.getSharedPreferences(WIPE_STATE_PREFS, Context.MODE_PRIVATE).getInt("wipe_attempts", 0)

    private fun raceFailures(result: WipeResult): List<String> =
        (result as? WipeResult.Incomplete)?.failedSteps.orEmpty().filter { it in raceSensitiveSteps }

    @Test
    fun concurrentWipesDoNotReportSpuriousFailedSteps() = runBlocking {
        AppLockStore(context).apply {
            setPin("48291374".toCharArray())
            enableLock()
        }

        val results = (1..4).map {
            async(Dispatchers.IO) { SecurityWipe.wipeAndResetApp(context) }
        }.awaitAll()

        results.forEachIndexed { index, result ->
            assertEquals(
                "wipe $index reported a failure only another concurrent wipe could have caused",
                emptyList<String>(),
                raceFailures(result),
            )
        }
    }

    /** The attempt counter belongs to a wipe EPISODE. Four overlapping runs must not spend four of
     *  the three-resume budget between them — past it, [LockedActivity] blocks the app for good. */
    @Test
    fun concurrentWipesDoNotEachBurnAResume() = runBlocking {
        val results = (1..4).map {
            async(Dispatchers.IO) { SecurityWipe.wipeAndResetApp(context) }
        }.awaitAll()

        // Serialised, each run starts from the marker the previous one cleared, so every one of
        // them is attempt 1. Racing, they interleave `markWipeInProgress` and the counter climbs.
        // Bounded by the number of runs that did NOT complete, so an environmental step failure
        // (see [raceSensitiveSteps]) does not turn this into a flake.
        val incomplete = results.count { it is WipeResult.Incomplete }
        assertTrue(
            "attempts=${attempts()} after 4 concurrent wipes ($incomplete incomplete): the counter " +
                "must advance per episode, not per caller",
            attempts() <= incomplete + 1,
        )
    }
}
