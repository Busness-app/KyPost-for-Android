package org.kysecurity.mail.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ContactDaoOrderingTest {

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
    fun observeAll_sortsSelfContactFirst_thenByNameCaseInsensitive() = runBlocking {
        dao.upsertAll(
            listOf(
                ContactEntity(uid = "1", rev = 1, fn = "Zack Test"),
                ContactEntity(uid = "2", rev = 1, fn = "Zzz Self", isSelf = true),
                ContactEntity(uid = "3", rev = 1, fn = "Bob Test"),
            ),
        )

        val results = dao.observeAll().first()

        // "Zzz Self" sorts last alphabetically but must come first because it's the self-contact —
        // this fixture only passes once ORDER BY actually prioritizes isSelf over fn.
        assertEquals(listOf("Zzz Self", "Bob Test", "Zack Test"), results.map { it.fn })
        assertEquals(true, results.first().isSelf)
    }
}
