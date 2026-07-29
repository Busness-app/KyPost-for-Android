package com.urlxl.mail

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

/**
 * The outbound half of the attachment size bound.
 *
 * `ComposeActivity.addAttachment` used to call `readBytes()` and check the 25 MB cap against
 * `bytes.size` — i.e. after the whole document was already in the heap — while
 * `OpenableColumns.SIZE` was read and then never used. Picking a large file from a cloud provider
 * was an `OutOfMemoryError`, which `runCatching` does not catch, so it was a hard crash with an
 * unsent message in flight. [readAtMost] is what makes the refusal happen before the allocation.
 */
class ComposeAttachmentReadTest {

    @Test
    fun readAtMost_readsAStreamThatFitsTheBudget() {
        val payload = ByteArray(200_000) { (it % 251).toByte() }
        assertArrayEquals(payload, readAtMost(ByteArrayInputStream(payload), payload.size.toLong()))
    }

    @Test
    fun readAtMost_readsAStreamExactlyOnTheBudget() {
        val payload = ByteArray(1024) { 7 }
        assertArrayEquals(payload, readAtMost(ByteArrayInputStream(payload), 1024L))
    }

    @Test
    fun readAtMost_throwsRatherThanTruncating() {
        // Returning the prefix is the failure mode this exists to prevent: almost every file format
        // reads a truncated file without complaining, so the recipient gets a corrupt attachment and
        // the sender is never told.
        val payload = ByteArray(4096)
        assertThrows(AttachmentTooLargeException::class.java) {
            readAtMost(ByteArrayInputStream(payload), 4095L)
        }
    }

    @Test
    fun readAtMost_refusesBeforeConsumingTheWholeSource() {
        // The bound has to hold on a stream whose length is not known up front — a provider that
        // under-reports or omits OpenableColumns.SIZE is exactly the case the declared-size
        // pre-check cannot catch.
        val counting = CountingStream(totalBytes = 64 * 1024 * 1024)
        assertThrows(AttachmentTooLargeException::class.java) {
            readAtMost(counting, 1024L)
        }
        // A few buffer-fills past the limit at most, not the whole 64 MB.
        assertEquals(true, counting.served < 1024 * 1024)
    }

    /** An endless-ish source that reports how much of itself was actually read. */
    private class CountingStream(private val totalBytes: Long) : InputStream() {
        var served = 0L
            private set

        override fun read(): Int = if (served++ < totalBytes) 0 else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (served >= totalBytes) return -1
            val n = minOf(len.toLong(), totalBytes - served).toInt()
            served += n
            return n
        }
    }
}
