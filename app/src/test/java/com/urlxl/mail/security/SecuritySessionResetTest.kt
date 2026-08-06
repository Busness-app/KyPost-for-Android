package com.urlxl.mail.security

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors

class SecuritySessionResetTest {

    /**
     * The load-bearing case: the caller's scope dies mid-change, and the reset must still run.
     *
     * This is the Hostile Location Protection toggle being interrupted by a Back press or a
     * rotation. The destructive work and the flag commit were already protected; the *reset* was
     * not, so the setting committed while the previous session's decrypted attachments and draft
     * stayed in the process.
     *
     * The outer scope deliberately uses a different dispatcher from the work context, because that
     * is what makes the continuation resume cancellably — the real pairing is
     * `Dispatchers.Main.immediate` outside and `Dispatchers.Default` inside. With one shared
     * dispatcher this bug is invisible.
     */
    @Test
    fun theResetRunsEvenWhenTheCallerIsCancelled() {
        val outerDispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        try {
            val changeStarted = CountDownLatch(1)
            val releaseChange = CountDownLatch(1)
            // AtomicBoolean rather than a plain var: the change and the reset run on Default while
            // the assertions run on the test thread, so the writes need to be visible across both.
            val changeRan = java.util.concurrent.atomic.AtomicBoolean(false)
            val resetRan = java.util.concurrent.atomic.AtomicBoolean(false)

            val outer = CoroutineScope(outerDispatcher)
            val job = outer.launch {
                runSecurityChangeThenReset(
                    workContext = Dispatchers.Default,
                    change = {
                        changeStarted.countDown()
                        releaseChange.await()
                        changeRan.set(true)
                    },
                    reset = { resetRan.set(true) },
                )
            }

            changeStarted.await()
            job.cancel()
            releaseChange.countDown()
            runBlocking { job.join() }

            assertTrue("the change itself must complete", changeRan.get())
            assertTrue("the session reset must not be skipped by the cancellation", resetRan.get())
        } finally {
            outerDispatcher.close()
        }
    }

    /** The ordinary path still works, and the reset runs after the change rather than beside it. */
    @Test
    fun theResetRunsAfterTheChangeOnTheUninterruptedPath() = runBlocking {
        val order = mutableListOf<String>()

        runSecurityChangeThenReset(
            workContext = Dispatchers.Default,
            change = { order += "change" },
            reset = { order += "reset" },
        )

        assertTrue("expected change then reset, got $order", order == listOf("change", "reset"))
    }
}
