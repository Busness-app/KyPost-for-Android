package org.kysecurity.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.WorkManagerTestInitHelper
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollmentStateWorkerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun initWorkManager() {
        // An executor that never runs anything. The point of this test is what was *enqueued*;
        // letting the real worker run would make a live, credentialed network call from a test.
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().setExecutor { }.build(),
        )
    }

    /**
     * The load-bearing one. WorkManager writes a request's input data to its own database in
     * plaintext, so a credential carried there would sit on disk outside every store this app
     * encrypts. The worker reads it from `SecurePairingStore` at run time instead — which only
     * holds if the request genuinely carries nothing.
     */
    @Test
    fun theRequestCarriesNoInputData() {
        assertEquals(0, EnrollmentStateWorker.buildRequest().workSpec.input.size())
    }

    /** Unique work, so a burst of teardowns cannot pile up a queue of reports that each spend
     *  device-auth budget to say the same thing. */
    @Test
    fun enqueueLeavesExactlyOneRequestUnderTheUniqueName() {
        EnrollmentStateWorker.enqueue(context)

        val infos = WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(EnrollmentStateWorker.UNIQUE_NAME).get()

        assertEquals(1, infos.size)
    }
}
