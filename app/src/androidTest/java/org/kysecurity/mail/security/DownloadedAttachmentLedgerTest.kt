package org.kysecurity.mail.security

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The ledger is the ONLY record of decrypted mail that escaped the sandbox into shared Downloads.
 * A row it drops is plaintext no later wipe can find, while the wipe reports the device as cleared
 * — so every ambiguous answer here has to resolve towards "still there".
 */
class DownloadedAttachmentLedgerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val row = Uri.parse("content://media/external/downloads/4242")

    @Before
    @After
    fun clearLedger() {
        context.deleteSharedPreferences(DownloadedAttachmentLedger.PREFS_NAME)
    }

    /** THE REGRESSION. `delete` returns 0 rows — ambiguous — and the follow-up `query` throws,
     *  which is what happens when this app no longer holds a read grant for a row it wrote (a
     *  reinstall, or the user moving the file). That threw exception used to be swallowed into
     *  `false`, read as "already gone", and the row was dropped from the ledger. */
    @Test
    fun aRowWhoseExistenceCannotBeCheckedStaysInTheLedger() {
        DownloadedAttachmentLedger.record(context, row)

        val stranded = DownloadedAttachmentLedger.deleteAll(
            context,
            delete = { 0 },
            resolves = { null },
        )

        assertEquals(listOf(row.toString()), stranded)
        assertEquals(
            "and it must be kept so a later sweep retries it",
            1,
            DownloadedAttachmentLedger.recordedCount(context),
        )
    }

    @Test
    fun aRowProvablyGoneIsDroppedFromTheLedger() {
        DownloadedAttachmentLedger.record(context, row)

        val stranded = DownloadedAttachmentLedger.deleteAll(
            context,
            delete = { 0 },
            resolves = { false },
        )

        assertTrue(stranded.isEmpty())
        assertEquals(0, DownloadedAttachmentLedger.recordedCount(context))
    }

    @Test
    fun aRowStillPresentAfterAZeroRowDeleteIsStranded() {
        DownloadedAttachmentLedger.record(context, row)

        val stranded = DownloadedAttachmentLedger.deleteAll(
            context,
            delete = { 0 },
            resolves = { true },
        )

        assertEquals(listOf(row.toString()), stranded)
    }

    @Test
    fun aThrownDeleteIsNeverASuccess() {
        DownloadedAttachmentLedger.record(context, row)

        val stranded = DownloadedAttachmentLedger.deleteAll(
            context,
            delete = { throw SecurityException("no grant") },
            resolves = { false },
        )

        assertEquals(listOf(row.toString()), stranded)
    }

    @Test
    fun aDeletedRowClearsTheLedgerFile() {
        DownloadedAttachmentLedger.record(context, row)

        val stranded = DownloadedAttachmentLedger.deleteAll(context, delete = { 1 }, resolves = { false })

        assertTrue(stranded.isEmpty())
        assertEquals(0, DownloadedAttachmentLedger.recordedCount(context))
    }

    /** [SecurityWipe] reads this before a sweep so a sweep that THROWS can still report a truthful
     *  number. It used to report a placeholder list's `.size` — the constant 1 — to the user as a
     *  fact, on the one screen whose purpose is saying what survived. */
    @Test
    fun recordedCountReportsEveryRowWithoutTouchingTheProvider() {
        repeat(7) { DownloadedAttachmentLedger.record(context, Uri.parse("content://media/external/downloads/$it")) }

        assertEquals(7, DownloadedAttachmentLedger.recordedCount(context))
    }
}
