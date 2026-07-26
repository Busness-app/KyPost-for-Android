package com.urlxl.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EphemeralAttachmentProviderTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun register_thenRead_roundTripsBytesAndMimeType() {
        val bytes = "hello attachment".toByteArray()
        // Snapshot the expectation BEFORE registering. register() retains this exact array and the
        // provider zeroes it once the pipe has been written, which is the whole point — plaintext
        // must not linger in the heap. Comparing against the original reference was therefore a
        // race: whether it passed depended on whether the writer thread's zeroing had run yet.
        val expected = bytes.copyOf()
        val uri = EphemeralAttachmentBytes.register(bytes, "text/plain")

        assertEquals("text/plain", context.contentResolver.getType(uri))

        val readBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        assertArrayEquals(expected, readBytes)
    }
}
