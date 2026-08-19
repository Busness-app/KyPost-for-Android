package org.kysecurity.mail.security

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

    /** AppRestart.relaunch no longer kills the process, so held plaintext must be cleared. */
    @Test
    fun clearingProcessScopedState_dropsAndZeroesHeldPlaintext() {
        val secret = "decrypted attachment plaintext".toByteArray()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain", "secret.txt"))

        org.kysecurity.mail.InMemoryPlaintext.clearAll()

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
        val uri = requireNotNull(EphemeralAttachmentBytes.register(bytes, "text/plain", "note.txt"))

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
        // Snapshot before registering: register() retains this array and the provider zeroes it.
        val expected = bytes.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(bytes, "text/plain", "note.txt"))

        assertEquals("text/plain", context.contentResolver.getType(uri))

        val readBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        assertArrayEquals(expected, readBytes)
    }

    /** Nothing bounded the map, so backing out of choosers accumulated decrypted mail in the heap. */
    @Test
    fun register_refusesOnceTheHeldPlaintextCeilingIsReached() {
        // Sized from the ceiling, not a literal: two that individually fit but together do not.
        val each = (org.kysecurity.mail.MemoryBudget.PENDING_ATTACHMENT_BYTES * 2 / 3).toInt()

        // The first must be kept and the second refused, rather than the first being silently
        // evicted out from under a pending viewer.
        val first = requireNotNull(EphemeralAttachmentBytes.register(ByteArray(each), "application/pdf", "big.pdf"))

        val second = EphemeralAttachmentBytes.register(ByteArray(each), "application/pdf", "big.pdf")
        assertNull(second)

        // The one that was accepted is still readable — a refusal must not disturb it.
        assertEquals("application/pdf", context.contentResolver.getType(first))
    }
}
