package org.kysecurity.mail.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ContactDaoSearchTest {

    private lateinit var db: AppDatabase
    private lateinit var dao: ContactDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            AppDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.contactDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun search_matchesNameCaseInsensitively() = runBlocking {
        dao.upsertAll(
            listOf(
                ContactEntity(uid = "1", rev = 1, fn = "Ada Lovelace", emailsJson = """[{"value":"ada@example.com"}]"""),
                ContactEntity(uid = "2", rev = 1, fn = "Bob Smith", emailsJson = """[{"value":"bob@example.com"}]"""),
            ),
        )

        val results = dao.search("ada")

        assertEquals(1, results.size)
        assertEquals("Ada Lovelace", results.first().fn)
    }

    /** The pin lookup must not be evictable by contact VOLUME. `search` is the autocomplete
     *  query — ORDER BY fn COLLATE NOCASE LIMIT 5 — and the relay supplies both the contact list
     *  and the keys it serves. Five decoy contacts carrying the pinned address and sorting ahead
     *  of the real one pushed the pin out of the result set entirely; `ClientEncryptedSender` read
     *  the empty lookup as "never pinned" and encrypted to whatever key the relay handed back. */
    @Test
    fun pinnedForEmail_survivesDecoyContactsCarryingTheSameAddress() = runBlocking {
        val pinned = "alice@example.com"
        dao.upsertAll(
            (1..5).map { n ->
                ContactEntity(uid = "decoy-$n", rev = 1, fn = "AAAA$n", emailsJson = """[{"value":"$pinned"}]""")
            } + ContactEntity(
                uid = "real",
                rev = 1,
                fn = "Zoe Real",
                emailsJson = """[{"value":"$pinned"}]""",
                pgpKey = "PINNED-KEY",
                pgpKeyFingerprint = "AAAA BBBB",
            ),
        )

        val results = dao.pinnedForEmail(pinned)

        assertTrue(
            "the pinned contact must survive any number of same-address decoys",
            results.any { it.uid == "real" },
        )
    }

    @Test
    fun search_matchesEmailAddress() = runBlocking {
        dao.upsertAll(
            listOf(ContactEntity(uid = "1", rev = 1, fn = "Ada Lovelace", emailsJson = """[{"value":"ada@example.com"}]""")),
        )

        val results = dao.search("example.com")

        assertEquals(1, results.size)
    }

    @Test
    fun search_excludesContactsWithNoEmail() = runBlocking {
        dao.upsertAll(listOf(ContactEntity(uid = "1", rev = 1, fn = "No Email Guy", emailsJson = "[]")))

        val results = dao.search("no email")

        assertTrue(results.isEmpty())
    }

    @Test
    fun search_ordersResultsByNameCaseInsensitive() = runBlocking {
        dao.upsertAll(
            listOf(
                ContactEntity(uid = "1", rev = 1, fn = "zack test", emailsJson = """[{"value":"zack@example.com"}]"""),
                ContactEntity(uid = "2", rev = 1, fn = "Amy test", emailsJson = """[{"value":"amy@example.com"}]"""),
            ),
        )

        val results = dao.search("test")

        assertEquals(listOf("Amy test", "zack test"), results.map { it.fn })
    }

    @Test
    fun search_treatsLikeWildcardsLiterallyAndLimitsResults() = runBlocking {
        dao.upsertAll(
            (1..6).map { index ->
                ContactEntity(
                    uid = "$index",
                    rev = 1,
                    fn = "Person $index%",
                    emailsJson = """[{"value":"person$index@example.com"}]""",
                )
            },
        )

        assertEquals(5, dao.search("Person").size)
        assertEquals(listOf("Person 1%"), dao.search("Person 1%").map { it.fn })
        assertTrue(dao.search("_").isEmpty())
    }
}
