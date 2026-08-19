package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    /** THE RACE. `peek` handed the SAME array to every concurrent opener, and the
     *  RejectedExecutionException path filled it unconditionally — so a reader still streaming
     *  that buffer got a half-zeroed file and no error. Revocation now defers the fill to the last
     *  release. */
    @Test
    fun revokingWhileAReaderHoldsTheBytesDoesNotZeroThemUnderIt() {
        val secret = "decrypted attachment plaintext".toByteArray()
        val expected = secret.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain", "secret.txt"))
        val token = requireNotNull(uri.lastPathSegment)

        val held = requireNotNull(EphemeralAttachmentBytes.acquire(token))

        // The capability goes immediately...
        assertTrue(EphemeralAttachmentBytes.revoke(token))
        assertNull("the token must stop resolving at once", context.contentResolver.getType(uri))
        // ...but the bytes the live reader is streaming must NOT be pulled out from under it.
        assertArrayEquals("a live read must not be corrupted by a revoke", expected, held.bytes)

        // And the moment that reader lets go, the plaintext is gone.
        EphemeralAttachmentBytes.release(held)
        assertArrayEquals(ByteArray(expected.size), held.bytes)
    }

    /** With no reader holding it, revocation zeroes inline rather than waiting for the TTL sweep. */
    @Test
    fun revokingAnUnreadAttachmentZeroesItImmediately() {
        val secret = "never opened".toByteArray()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain", "x.txt"))

        assertTrue(EphemeralAttachmentBytes.revoke(requireNotNull(uri.lastPathSegment)))

        assertArrayEquals(ByteArray(secret.size), secret)
    }

    /** Bytes are bounded by the READ's end now, not only by the 60s TTL: the last release of an
     *  expired attachment zeroes it. */
    @Test
    fun theLastReleaseAfterExpiryZeroesTheBytes() {
        val secret = "decrypted".toByteArray()
        val expected = secret.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain", "x.txt"))
        val token = requireNotNull(uri.lastPathSegment)

        val held = requireNotNull(EphemeralAttachmentBytes.acquire(token))
        // Sweep it while the read is in flight; a deterministic sweep, not a wait on the timer.
        EphemeralAttachmentBytes.purgeExpired(System.currentTimeMillis() + 10 * 60_000L)

        assertArrayEquals("still readable while a reader holds it", expected, held.bytes)

        EphemeralAttachmentBytes.release(held)
        assertArrayEquals(ByteArray(expected.size), held.bytes)
    }

    /** Two readers, and only the second release may zero. */
    @Test
    fun zeroingWaitsForEveryReader() {
        val secret = "decrypted".toByteArray()
        val expected = secret.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(secret, "text/plain", "x.txt"))
        val token = requireNotNull(uri.lastPathSegment)

        val first = requireNotNull(EphemeralAttachmentBytes.acquire(token))
        val second = requireNotNull(EphemeralAttachmentBytes.acquire(token))
        EphemeralAttachmentBytes.revoke(token)

        EphemeralAttachmentBytes.release(first)
        assertArrayEquals("one reader remains", expected, second.bytes)

        EphemeralAttachmentBytes.release(second)
        assertArrayEquals(ByteArray(expected.size), second.bytes)
    }

    /** A viewer that probes for type or size before reading must still be able to reopen: this is
     *  why the token is not consumed on first open, and the refcount is what makes that safe. */
    @Test
    fun aTokenStaysOpenableAcrossRepeatedReads() {
        val bytes = "reopen me".toByteArray()
        val expected = bytes.copyOf()
        val uri = requireNotNull(EphemeralAttachmentBytes.register(bytes, "text/plain", "note.txt"))

        repeat(3) {
            val read = context.contentResolver.openInputStream(uri).use { requireNotNull(it).readBytes() }
            assertArrayEquals(expected, read)
        }
    }
}
