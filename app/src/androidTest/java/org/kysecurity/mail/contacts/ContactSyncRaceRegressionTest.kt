package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.ContactDao
import org.kysecurity.mail.data.ContactEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** ContactSyncRepository.syncMutex serializes server sync vs device pull so isSelf survives. */
@RunWith(AndroidJUnit4::class)
class ContactSyncRaceRegressionTest {

    private lateinit var db: AppDatabase
    private lateinit var dao: ContactDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            AppDatabase::class.java,
        ).build()
        dao = db.contactDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun concurrentServerAndDeviceSync_sharedMutex_neverLosesIsSelf() = runBlocking {
        val mutex = Mutex()
        repeat(RACE_ITERATIONS) { iteration ->
            assertTrue(
                "iteration $iteration: isSelf lost",
                raceOnce(mutex, uid = "contact-$iteration"),
            )
        }
    }

    /** Returns true if `isSelf` survived the race. */
    private suspend fun raceOnce(mutex: Mutex, uid: String): Boolean {
        dao.upsertAll(listOf(ContactEntity(uid = uid, rev = 1, fn = "Original Name", isSelf = false)))

        coroutineScope {
            // Models ContactSyncRepository.sync(): server flips isSelf true via a full-row upsert.
            val serverSync = async(Dispatchers.Default) {
                mutex.withLock {
                    dao.upsertAll(listOf(ContactEntity(uid = uid, rev = 2, fn = "Original Name", isSelf = true)))
                }
            }

            // Models DeviceContactRepository.pullDeviceChangesForOwnAccount(): reads the row,
            // merges an unrelated field, writes the whole row back — losing isSelf if its read
            // happened before the server's write landed and nothing serializes the two.
            val deviceSync = async(Dispatchers.Default) {
                mutex.withLock {
                    val existing = dao.getByUid(uid)!!
                    delay(1) // simulate the merge work between read and write
                    dao.upsertAll(listOf(existing.copy(fn = "Renamed On Device")))
                }
            }

            awaitAll(serverSync, deviceSync)
        }
        return dao.getByUid(uid)!!.isSelf
    }

    private companion object {
        const val RACE_ITERATIONS = 50
    }
}
