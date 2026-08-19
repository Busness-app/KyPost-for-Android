package org.kysecurity.mail

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

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
        val payload = ByteArray(4096)
        assertThrows(AttachmentTooLargeException::class.java) {
            readAtMost(ByteArrayInputStream(payload), 4095L)
        }
    }

    @Test
    fun readAtMost_refusesBeforeConsumingTheWholeSource() {
        // A provider may under-report or omit OpenableColumns.SIZE, so length is unknown up front.
        val counting = CountingStream(totalBytes = 64 * 1024 * 1024)
        assertThrows(AttachmentTooLargeException::class.java) {
            readAtMost(counting, 1024L)
        }
        // A few buffer-fills past the limit at most, not the whole 64 MB.
        assertEquals(true, counting.served < 1024 * 1024)
    }

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
