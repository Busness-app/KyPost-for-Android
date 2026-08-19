package org.kysecurity.mail.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** clearServerDecryptedBodies against real SQL; the JVM fake only mirrors the predicate. */
@RunWith(AndroidJUnit4::class)
class EmailDaoClearDecryptedTest {

    private lateinit var db: AppDatabase
    private lateinit var dao: EmailDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            AppDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.emailDao()
    }

    @After
    fun tearDown() = db.close()

    private fun row(
        id: String,
        pgpEncrypted: Boolean,
        body: String?,
    ) = EmailEntity(
        messageId = id,
        folder = "INBOX",
        sender = "sender@example.com",
        subject = "Subject $id",
        preview = body.orEmpty(),
        body = body,
        sourceMode = "relay",
        pgpEncrypted = pgpEncrypted,
    )

    @Test
    fun itClearsOnlyTheMailTheServerDecrypted() {
        dao.upsertAll(
            listOf(
                // Encrypted with a body: the server opened it with an account key it held. The row
                // this exists for.
                row("decrypted", pgpEncrypted = true, body = "<p>the plaintext</p>"),
                // Ordinary mail. Clearing it would be collateral for no privacy gain.
                row("plain", pgpEncrypted = false, body = "<p>lunch?</p>"),
                // Already client-protected: nothing cached to drop.
                row("protected", pgpEncrypted = true, body = ""),
                // A null body must not throw or be counted.
                row("nullbody", pgpEncrypted = true, body = null),
            ),
        )

        assertEquals("only the server-decrypted row", 1, dao.clearServerDecryptedBodies())

        val cleared = dao.getById("decrypted")!!
        assertEquals("", cleared.body)
        assertEquals("the preview is derived from the plaintext too", "", cleared.preview)
        assertEquals("the row itself must survive", "Subject decrypted", cleared.subject)

        assertEquals("<p>lunch?</p>", dao.getById("plain")!!.body)
        assertEquals("<p>lunch?</p>", dao.getById("plain")!!.preview)
        assertEquals("", dao.getById("protected")!!.body)
        assertEquals(null, dao.getById("nullbody")!!.body)
    }

    /** Idempotent: a second enrollment on the same device must not report work it did not do. */
    @Test
    fun aSecondRunClearsNothing() {
        dao.upsertAll(listOf(row("decrypted", pgpEncrypted = true, body = "<p>the plaintext</p>")))

        assertEquals(1, dao.clearServerDecryptedBodies())
        assertEquals(0, dao.clearServerDecryptedBodies())
    }
}
