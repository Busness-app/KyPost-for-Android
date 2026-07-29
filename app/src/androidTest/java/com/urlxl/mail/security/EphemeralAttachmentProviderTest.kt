package com.urlxl.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EphemeralAttachmentProviderTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @After
    fun tearDown() {
        EphemeralAttachmentBytes.resetForNewSession()
    }

    /**
     * The wipe path, which this holder was invisible to.
     *
     * [EphemeralAttachmentBytes] parks up to 64 MB of decrypted attachment plaintext in a
     * process-scoped object, and `AppRestart.relaunch` no longer kills the process — so a security
     * wipe used to run to completion, relaunch into the same JVM and leave every registered
     * attachment readable in the attacker's session. It was never added to `InMemoryPlaintext`,
     * whose KDoc had explicitly invited exactly this kind of holder to register.
     */
    @Test
    fun clearingProcessScopedState_dropsAndZeroesHeldPlaintext() {
        val secret = "decrypted attachment plaintext".toByteArray()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain"))

        com.urlxl.mail.InMemoryPlaintext.clearAll()

        // Gone from the map: the token no longer resolves to anything.
        assertNull(context.contentResolver.getType(uri))
        // And zeroed in place, not merely unreferenced — until the collector runs, an unzeroed
        // buffer is still readable in a heap dump.
        assertArrayEquals(ByteArray(secret.size), secret)
    }

    /** `openFile` used to accept and discard `mode`, handing a writer a read-only pipe end — after
     *  take() had already consumed the single-use token, so the retry failed differently. */
    @Test
    fun openFile_refusesWriteModesWithoutConsumingTheToken() {
        val bytes = "hello attachment".toByteArray()
        val expected = bytes.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(bytes, "text/plain"))

        try {
            context.contentResolver.openFileDescriptor(uri, "w")
            throw AssertionError("Expected a write mode to be refused")
        } catch (expectedFailure: SecurityException) {
            // The refusal is the assertion.
        }

        // Still intact and readable: the refused open must not have consumed it.
        val readBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        assertArrayEquals(expected, readBytes)
    }

    @Test
    fun register_thenRead_roundTripsBytesAndMimeType() {
        val bytes = "hello attachment".toByteArray()
        // Snapshot the expectation BEFORE registering. register() retains this exact array and the
        // provider zeroes it once the pipe has been written, which is the whole point — plaintext
        // must not linger in the heap. Comparing against the original reference was therefore a
        // race: whether it passed depended on whether the writer thread's zeroing had run yet.
        val expected = bytes.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(bytes, "text/plain"))

        assertEquals("text/plain", context.contentResolver.getType(uri))

        val readBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        assertArrayEquals(expected, readBytes)
    }

    /**
     * The held-plaintext ceiling. MAX_CONCURRENT_WRITES bounded writer *threads*; nothing bounded
     * the map, so tapping attachments and backing out of each chooser — which never calls `take` —
     * accumulated decrypted mail in the heap until the process died, on the one path whose premise
     * is that this plaintext is short-lived.
     */
    @Test
    fun register_refusesOnceTheHeldPlaintextCeilingIsReached() {
        // Two 40 MB registrations exceed the 64 MB ceiling; the first must be kept and the second
        // refused, rather than the first being silently evicted out from under a pending viewer.
        val first = requireNotNull(EphemeralAttachmentBytes.register(ByteArray(40 * 1024 * 1024), "application/pdf"))

        val second = EphemeralAttachmentBytes.register(ByteArray(40 * 1024 * 1024), "application/pdf")
        assertNull(second)

        // The one that was accepted is still readable — a refusal must not disturb it.
        assertEquals("application/pdf", context.contentResolver.getType(first))
    }
}
