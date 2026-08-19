package org.kysecurity.mail.security

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

    /** The outer scope needs a different dispatcher from workContext, or the bug hides. */
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
