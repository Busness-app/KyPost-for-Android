package org.kysecurity.mail.security

import android.content.Context
import android.provider.MediaStore
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * Saving an attachment puts DECRYPTED mail outside the sandbox. A save that reports failure must
 * leave nothing behind: the row used to be inserted, half-written and then abandoned, so "save
 * failed" could still mean a readable fragment of the message sitting in Downloads.
 */
class AttachmentDownloadCleanupTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    /** Unique per run, so a leftover row from an earlier run cannot make this test pass or fail. */
    private val name = "kypost-attachment-cleanup-${System.nanoTime()}.txt"

    @Before
    @After
    fun clearDownloadsAndLedger() {
        context.contentResolver.delete(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            "${MediaStore.Downloads.DISPLAY_NAME} LIKE ?",
            arrayOf("kypost-attachment-cleanup-%"),
        )
        context.deleteSharedPreferences(DownloadedAttachmentLedger.PREFS_NAME)
    }

    @Test
    fun aFailedWriteLeavesNothingInDownloads() {
        val saved = saveAttachmentToDownloads(context, name, "text/plain", "secret".toByteArray()) { _, _ ->
            throw IOException("No space left on device")
        }

        assertFalse(saved)
        assertEquals("a partial decrypted attachment must not survive a failed save", 0, rows().size)
    }

    /** The ledger keeps the entry even though the row is gone: it is the only record of a file
     *  outside the sandbox, and a wipe that finds it already deleted has lost nothing. */
    @Test
    fun aFailedWriteStaysInTheLedgerForTheWipeToSweep() {
        saveAttachmentToDownloads(context, name, "text/plain", "secret".toByteArray()) { _, _ ->
            throw IOException("No space left on device")
        }

        assertEquals(1, DownloadedAttachmentLedger.recordedCount(context))
    }

    @Test
    fun aSuccessfulSavePublishesTheWholePayload() {
        val bytes = "the whole attachment".toByteArray()

        assertTrue(saveAttachmentToDownloads(context, name, "text/plain", bytes))

        val saved = rows()
        assertEquals(1, saved.size)
        val (id, pending) = saved.single()
        assertEquals("a published row must not still be pending", 0, pending)
        val uri = android.content.ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, id)
        assertArrayEquals(bytes, context.contentResolver.openInputStream(uri)!!.use { it.readBytes() })
    }

    /** Id and IS_PENDING for every row this test could have created. The owning app sees its own
     *  pending rows, so an abandoned half-written file would be counted here. */
    private fun rows(): List<Pair<Long, Int>> =
        context.contentResolver.query(
            MediaStore.Downloads.EXTERNAL_CONTENT_URI,
            arrayOf(MediaStore.Downloads._ID, MediaStore.Downloads.IS_PENDING),
            "${MediaStore.Downloads.DISPLAY_NAME} LIKE ?",
            arrayOf("kypost-attachment-cleanup-%"),
            null,
        )?.use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(cursor.getLong(0) to cursor.getInt(1))
            }
        }.orEmpty()
}
