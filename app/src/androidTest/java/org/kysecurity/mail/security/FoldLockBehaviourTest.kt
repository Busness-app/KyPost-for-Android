// androidx.security-crypto is deprecated in full with no replacement API; [AppLockSnapshot] below
// has to speak the same at-rest format AppLockStore does, so it carries the same suppression the
// production file carries.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.app.Activity
import android.app.Application
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.mail.MailRuntime

/**
 * The three halves of the foldable lock contract. A live resize must not lock; a close-and-lock
 * must; and, unique to this feature, two embedded panes locking at once must still collapse into
 * one unlock prompt. None is assumed anywhere in this feature — all three are asserted here.
 *
 * **These tests only mean anything with the app lock enabled and a PIN configured**, which is not
 * the shipped default ([AppLockStore.isLockEnabled] returns false on a clean install). Without the
 * setup below, [AppLockManager.lockNow] does not set the locked flag at all: the two locking tests
 * fail, and the resize test passes vacuously because nothing could have locked it in the first
 * place.
 *
 * **No [androidx.test.core.app.ActivityScenario] anywhere in this class.** Every screen here is a
 * [LockedActivity], and a [LockedActivity] under a lock `finish()`es itself from `onCreate`
 * ([LockedActivity.redirectToUnlockIfLocked]) — which is precisely the property being asserted.
 * `ActivityScenario.recreate()` blocks until the recreated Activity reaches `RESUMED` and
 * `onActivity {}` requires a live instance, so both fail on the Activity they are meant to observe:
 * the gate that works reads as "Activity never becomes requested state [RESUMED]". An
 * [Instrumentation.ActivityMonitor] can observe an Activity that finishes itself during startup,
 * so the launches, the recreates and the redirect are all driven and observed through monitors and
 * a process-wide [Application.ActivityLifecycleCallbacks] instead.
 *
 * **This class must never be able to trigger [SecurityWipe].** A test that can wipe the app under
 * test destroys the mail cache, the pairing, the PGP key envelope and the app-lock config on
 * whatever device it runs on. Exactly one PIN attempt is made per test — in [enableTheAppLock],
 * with the PIN written on the line above it — so the failed-attempt count this class can contribute
 * is provably at most one against a [LockoutPolicy.WIPE_THRESHOLD] of ten, and
 * [restoreTheAppLockStateAsFound] puts the stored counter back where it found it either way.
 * Nothing here calls [AppLockStore.reset]: see [AppLockSnapshot].
 */
@RunWith(AndroidJUnit4::class)
class FoldLockBehaviourTest {

    private val instrumentation: Instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext
    private val application: Application get() = context.applicationContext as Application

    private val graph get() = SecurityRuntime.graph(context)
    private val appLockManager get() = graph.appLockManager

    /** The graph's own store, not a fresh [AppLockStore]: reading it through the graph is what
     *  guarantees the graph — and therefore the [AppLockManager] whose `_locked` is seeded from
     *  `isLockEnabled()` at construction — already exists before the lock is switched on. */
    private val appLockStore get() = graph.appLockStore

    private lateinit var snapshot: AppLockSnapshot
    private lateinit var activities: ActivityTracker

    @Before
    fun enableTheAppLock() = runBlocking {
        // Before the first write below, and before anything can throw: this is the only record of
        // what has to be handed back.
        snapshot = AppLockSnapshot.capture(context)
        activities = ActivityTracker()
        application.registerActivityLifecycleCallbacks(activities)

        appLockStore.setPin(TEST_PIN.toCharArray())
        // Before the one attempt below, so a lockout left armed by an earlier class cannot turn it
        // into a Rejected — which is the only shape in which this class could ever contribute to
        // the wipe counter at all.
        appLockStore.resetFailedAttempts()
        appLockStore.enableLock()
        // Enabled but NOT engaged. attemptPin is the only supported way to clear the locked flag
        // without a biometric CryptoObject, and it is what makes the resize test a real assertion
        // rather than a tautology — the lock is armed, and the recreate must still not trip it.
        assertEquals(
            "Setup failed: the app lock could not be brought to enabled-and-unlocked.",
            UnlockAttemptResult.Success,
            appLockManager.attemptPin(TEST_PIN.toCharArray()),
        )
        // A background grace window armed by an earlier test class would expire mid-test and lock
        // the app for reasons that have nothing to do with folding.
        appLockManager.cancelScheduledLock()
        assertFalse(appLockManager.isLockedNow())
    }

    /**
     * Hands the process back exactly as it was found, on every exit path including an assertion
     * failure — JUnit runs this whatever the test body did.
     *
     * Ordering is the point, and each step is here because leaving it out cascade-fails a later
     * class rather than this one:
     *
     * 1. Every Activity this class started is finished first. A [UnlockActivity] left alive is
     *    `singleInstance`, so the next test's first redirect would land on it as `onNewIntent` and
     *    the "exactly one prompt" count would read zero.
     * 2. The app-lock files are restored from [AppLockSnapshot] rather than cleared. `reset()`
     *    would leave the next class with no PIN, no lock and — worse on a real device — no
     *    credential salt, which makes an already-wrapped `deviceSecret` undecryptable.
     * 3. The graphs that cache a DAO handle are dropped. This class is the first in the run to
     *    launch [InboxActivity], so it is the first to build [org.kysecurity.mail.mail.MailGraph],
     *    which captures `DataRuntime.graph(...).database.emailDao()` at construction. `SecurityWipeTest`
     *    and `WipeResurrectionTest` run later in this same package and close that database
     *    ([SecurityWipe.closeAndDeleteDatabase]) without the [AppRestart] relaunch production always
     *    performs — so the handle cached here is what `InboxRailTest` later reads through, and
     *    "connection is closed" on a background executor thread is an uncaught exception, i.e. a
     *    process kill. [org.kysecurity.mail.data.DataRuntime] is deliberately NOT invalidated: it
     *    owns the open database, and dropping it without closing it would orphan a second live
     *    handle on `kypost_mail.db` and make the later wipes fail to delete the file.
     * 4. [SecurityRuntime] goes too, so the next [AppLockManager] seeds `_locked` from the restored
     *    state instead of carrying this class's in-memory unlock.
     */
    @After
    fun restoreTheAppLockStateAsFound() {
        try {
            // isInitialized, because JUnit runs this even when the setup above threw part-way —
            // and a teardown that dies on an uninitialised field reports itself instead of the
            // failure that caused it, while leaving every restore below undone.
            if (::activities.isInitialized) {
                try {
                    finishEveryActivityStartedHere()
                } finally {
                    application.unregisterActivityLifecycleCallbacks(activities)
                }
            }
        } finally {
            if (::snapshot.isInitialized) snapshot.restore()
            MailRuntime.invalidate()
            ContactsRuntime.invalidate()
            DeviceContactsRuntime.invalidate()
            SecurityRuntime.invalidate()
        }
    }

    @Test
    fun aLiveResizeDoesNotEngageTheAppLock() {
        assertTrue(
            "Vacuous unless the lock is armed — lockNow() is a no-op with the lock disabled.",
            appLockStore.isLockEnabled(),
        )

        val inbox = startPane(InboxActivity::class.java)
        val recreated = awaitCreated(InboxActivity::class.java) {
            instrumentation.runOnMainSync { inbox.recreate() }
        }
        assertNotNull("The inbox was never recreated, so nothing was asserted.", recreated)

        assertFalse(
            "A configuration-change recreate must not lock the app — every unfold would prompt for a PIN.",
            appLockManager.isLockedNow(),
        )
    }

    @Test
    fun lockNowStillGatesTheInbox() {
        val inbox = startPane(InboxActivity::class.java)

        appLockManager.lockNow()

        // Both monitors are registered before the trigger: the redirect happens synchronously
        // inside the recreated Activity's onCreate, so a monitor added afterwards would miss it.
        val inboxMonitor = instrumentation.addMonitor(InboxActivity::class.java.name, null, false)
        val unlockMonitor = instrumentation.addMonitor(UnlockActivity::class.java.name, null, false)
        try {
            instrumentation.runOnMainSync { inbox.recreate() }

            val recreated = inboxMonitor.waitForActivityWithTimeout(LAUNCH_TIMEOUT_MS)
            assertNotNull("The inbox was never recreated, so nothing was asserted.", recreated)
            assertNotNull(
                "A locked app must send the gated screen to the unlock prompt.",
                unlockMonitor.waitForActivityWithTimeout(LAUNCH_TIMEOUT_MS),
            )
            assertTrue(
                "A locked app must finish a gated screen rather than leave it under the prompt.",
                awaitFinished(recreated),
            )
        } finally {
            instrumentation.removeMonitor(inboxMonitor)
            instrumentation.removeMonitor(unlockMonitor)
        }
    }

    /**
     * Before Activity Embedding, two [LockedActivity] instances could never be visible at once —
     * this test's whole premise is a code path that has never existed in this app until this
     * feature. [InboxActivity] as the primary pane and [EmailDetailActivity] as the secondary
     * stand in for a split; locking both, independently, each redirects to [UnlockActivity] and
     * `finish()`es itself ([LockedActivity.redirectToUnlockIfLocked]). [UnlockActivity] is
     * `android:launchMode="singleInstance"` (`AndroidManifest.xml`, around `:186`), so the second
     * `startActivity` call is contractually required to resolve against the instance the first
     * call created rather than starting a new one — that collapse, not merely "both panes gate",
     * is the property this test exists for.
     *
     * [Application.ActivityLifecycleCallbacks] observes `onActivityCreated` process-wide, which is
     * the one signal that distinguishes "the second call was routed to the existing singleInstance"
     * from "the second call created a stacked second prompt": `singleInstance` delivery to an
     * existing instance is [Activity.onNewIntent], not a fresh `onCreate`. This is a direct
     * assertion of the launch-mode contract, not a proxy for it.
     *
     * The two panes are gated one at a time, and deliberately by different halves of the gate. A CI
     * emulator has no real split, so only the top pane is ever `RESUMED` — and `Activity.recreate()`
     * on a stopped Activity is documented to defer until it is next visited, which would make a
     * "recreate both" version of this test assert nothing about the primary. So the secondary is
     * driven through [Activity.recreate] (the configuration change a fold produces, gated in
     * `onCreate`) and the primary by being started again (gated in `onStart`; see
     * [LockedActivity.onStart], "the app can lock while this screen sits in the back stack"). Both
     * are real, independent `startActivity(UnlockActivity)` calls from [LockedActivity], which is
     * all the collapse assertion needs.
     */
    @Test
    fun lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt() {
        val primary = startPane(InboxActivity::class.java)
        val secondary = startPaneFrom(primary, EmailDetailActivity::class.java) {
            putExtra("email_id", "test-message-1")
            putExtra("email_folder", "INBOX")
        }
        assertEquals(
            "Precondition: an unlock prompt left alive by earlier work would absorb both " +
                "redirects and make the count below meaningless.",
            0,
            activities.unlockPromptsCreated.get(),
        )

        appLockManager.lockNow()

        val gatedSecondary = awaitCreated(EmailDetailActivity::class.java) {
            instrumentation.runOnMainSync { secondary.recreate() }
        }
        assertNotNull("The secondary pane was never recreated, so nothing was asserted.", gatedSecondary)
        assertTrue(
            "The secondary pane must not survive a lock underneath its own prompt.",
            awaitFinished(gatedSecondary),
        )

        // singleTop, and it is the top of its own task by now, so this normally reaches the live
        // instance as onNewIntent + onStart and no second instance is created. Whichever instance
        // the system routes to is the one that ran the gate, and it is the one asserted on.
        val gatedPrimary = awaitCreated(InboxActivity::class.java, NO_NEW_INSTANCE_TIMEOUT_MS) {
            context.startActivity(
                Intent(context, InboxActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        } ?: primary
        assertTrue(
            "The primary pane must not survive a lock underneath its own prompt.",
            awaitFinished(gatedPrimary),
        )

        assertEquals(
            "Two embedded panes locking at once must collapse into ONE unlock " +
                "prompt via UnlockActivity's singleInstance launch mode, not stack two.",
            1,
            activities.unlockPromptsCreated.get(),
        )
    }

    // ---- Activity plumbing -------------------------------------------------------------------

    /** Starts [cls] in its own task and waits for it to reach `RESUMED`. Only for the unlocked
     *  set-up launches: a gated screen never gets there, which is what [awaitCreated] is for. */
    private fun <T : Activity> startPane(cls: Class<T>, configure: Intent.() -> Unit = {}): T =
        awaitResumedPane(cls) {
            context.startActivity(
                Intent(context, cls).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).apply(configure),
            )
        }

    /** As [startPane], but started *from* [parent] so the two panes share one task — which is what
     *  makes them a split rather than two unrelated screens. */
    private fun <T : Activity> startPaneFrom(
        parent: Activity,
        cls: Class<T>,
        configure: Intent.() -> Unit = {},
    ): T = awaitResumedPane(cls) {
        val intent = Intent(context, cls).apply(configure)
        instrumentation.runOnMainSync { parent.startActivity(intent) }
    }

    private fun <T : Activity> awaitResumedPane(cls: Class<T>, start: () -> Unit): T {
        val activity = awaitCreated(cls, trigger = start)
        assertNotNull("${cls.simpleName} never started.", activity)
        assertTrue("${cls.simpleName} never reached RESUMED.", awaitResumed(activity!!))
        return activity
    }

    /**
     * Runs [trigger] with a monitor already registered for [cls] and returns the instance it
     * created, or null if none was within [timeoutMs].
     *
     * The monitor goes up first because a gated screen redirects and finishes from inside
     * `onCreate`; anything that looks for it afterwards is looking for an Activity that is
     * already gone.
     */
    @Suppress("UNCHECKED_CAST")
    private fun <T : Activity> awaitCreated(
        cls: Class<T>,
        timeoutMs: Long = LAUNCH_TIMEOUT_MS,
        trigger: () -> Unit,
    ): T? {
        val monitor = instrumentation.addMonitor(cls.name, null, false)
        return try {
            trigger()
            val activity = monitor.waitForActivityWithTimeout(timeoutMs) as T?
            instrumentation.waitForIdleSync()
            activity
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    /** `finish()` is asynchronous, so reading the flag once races the redirect that set it. */
    private fun awaitFinished(activity: Activity?): Boolean {
        if (activity == null) return false
        return awaitOnMain { activity.isFinishing || activity.isDestroyed }
    }

    private fun awaitResumed(activity: Activity): Boolean = awaitOnMain { activities.isResumed(activity) }

    private fun awaitOnMain(condition: () -> Boolean): Boolean {
        val deadline = SystemClock.uptimeMillis() + SETTLE_TIMEOUT_MS
        while (true) {
            var satisfied = false
            instrumentation.runOnMainSync { satisfied = condition() }
            if (satisfied) return true
            if (SystemClock.uptimeMillis() >= deadline) return false
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    /**
     * Leaves no Activity of this class's making behind, however the test exited.
     *
     * Loops rather than sweeping once: finishing a gated pane can itself start a [UnlockActivity]
     * that was not in the first snapshot, and that is exactly the instance whose survival would
     * absorb the next test's first redirect.
     */
    private fun finishEveryActivityStartedHere() {
        val deadline = SystemClock.uptimeMillis() + SETTLE_TIMEOUT_MS
        while (true) {
            val live = activities.live()
            if (live.isEmpty()) break
            instrumentation.runOnMainSync { live.forEach { if (!it.isFinishing) it.finish() } }
            if (SystemClock.uptimeMillis() >= deadline) break
            Thread.sleep(POLL_INTERVAL_MS)
        }
        instrumentation.waitForIdleSync()
    }

    /**
     * Process-wide record of what this class started, and of every [UnlockActivity] `onCreate`.
     *
     * The creation count is the whole of the collapse assertion: `singleInstance` delivery to a
     * live instance is [Activity.onNewIntent], so a second `onCreate` is exactly and only what "the
     * system stacked a second prompt" looks like.
     */
    private class ActivityTracker : Application.ActivityLifecycleCallbacks {
        private val liveActivities = Collections.synchronizedList(mutableListOf<Activity>())
        private val resumedActivities = Collections.synchronizedList(mutableListOf<Activity>())
        val unlockPromptsCreated = AtomicInteger(0)

        fun live(): List<Activity> = synchronized(liveActivities) { liveActivities.toList() }
        fun isResumed(activity: Activity): Boolean =
            synchronized(resumedActivities) { resumedActivities.contains(activity) }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            if (activity is UnlockActivity) unlockPromptsCreated.incrementAndGet()
            synchronized(liveActivities) { liveActivities.add(activity) }
        }

        override fun onActivityResumed(activity: Activity) {
            synchronized(resumedActivities) { resumedActivities.add(activity) }
        }

        override fun onActivityPaused(activity: Activity) {
            synchronized(resumedActivities) { resumedActivities.remove(activity) }
        }

        override fun onActivityDestroyed(activity: Activity) {
            synchronized(liveActivities) { liveActivities.remove(activity) }
            synchronized(resumedActivities) { resumedActivities.remove(activity) }
        }

        override fun onActivityStarted(activity: Activity) = Unit
        override fun onActivityStopped(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    }

    private companion object {
        const val TEST_PIN = "482913"
        const val LAUNCH_TIMEOUT_MS = 15_000L
        const val SETTLE_TIMEOUT_MS = 10_000L

        /** Short on purpose: the expected outcome of restarting a `singleTop` Activity that is
         *  already the top of its task is that no new instance appears at all, and this is how long
         *  the test waits to be sure of it. */
        const val NO_NEW_INSTANCE_TIMEOUT_MS = 3_000L
        const val POLL_INTERVAL_MS = 50L
    }
}

/**
 * A verbatim copy of both app-lock preference files, taken before this class overwrites them and
 * written back afterwards.
 *
 * [AppLockStore.reset] is not a restore. It clears the credential salt — which makes an already
 * wrapped `deviceSecret` undecryptable, so a device that ran this suite would silently need
 * re-pairing — and it leaves whatever ran next with no PIN and no lock, neither of which is
 * necessarily what was there before. The store exposes no way to read the PIN hash back, so the
 * only honest restore is at the file level.
 *
 * The tripwire file is written **after** the encrypted one on the way back, for the same reason
 * [AppLockStore.reset] clears it first: `tripwireBroken()` is "a lock was configured but the PIN
 * hash is gone", so the moment where the marker is set and the hash is not must not exist. Getting
 * that order wrong here would arm [SecurityWipe.enforceTripwire] to destroy the device's data on
 * its next launch, from a teardown.
 */
private class AppLockSnapshot(
    private val context: Context,
    private val secure: Map<String, Any?>,
    private val tripwire: Map<String, Any?>,
) {

    fun restore() {
        write(securePrefs(context), secure)
        write(context.getSharedPreferences(TRIPWIRE_FILE, Context.MODE_PRIVATE), tripwire)
    }

    private fun write(prefs: android.content.SharedPreferences, values: Map<String, Any?>) {
        val editor = prefs.edit().clear()
        values.forEach { (key, value) ->
            when (value) {
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
                is String -> editor.putString(key, value)
                // Loud rather than silent: an unrestored key is app-lock state this class ate.
                else -> error("Cannot restore app-lock preference '$key' of type ${value?.javaClass}")
            }
        }
        editor.commit()
    }

    companion object {
        /** Must match [AppLockStore]'s own file names and key scheme, or this reads and writes a
         *  different file than the one under test. */
        private const val SECURE_FILE = "app_lock_secure"
        private const val TRIPWIRE_FILE = "app_lock_tripwire"

        fun capture(context: Context): AppLockSnapshot {
            val appContext = context.applicationContext
            return AppLockSnapshot(
                context = appContext,
                secure = securePrefs(appContext).all.toMap(),
                tripwire = appContext.getSharedPreferences(TRIPWIRE_FILE, Context.MODE_PRIVATE).all.toMap(),
            )
        }

        private fun securePrefs(context: Context): android.content.SharedPreferences {
            val masterKey = MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context.applicationContext,
                SECURE_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }
    }
}
