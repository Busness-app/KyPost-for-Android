package org.kysecurity.mail.data

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.security.HostileLocationSettings
import org.kysecurity.mail.security.SecurityWipe
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DataGraphHostileLocationTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @After
    fun cleanUp() {
        HostileLocationSettings(context).setEnabled(false)
        context.deleteDatabase("kypost_mail.db")
    }

    @Test
    fun disabled_createsOnDiskDatabaseFile() {
        HostileLocationSettings(context).setEnabled(false)
        val graph = DataGraph(context)
        graph.database.openHelper.writableDatabase // force creation
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertTrue(dbFile.exists())
        graph.database.close()
    }

    @Test
    fun enabled_neverCreatesAnOnDiskDatabaseFile() {
        context.deleteDatabase("kypost_mail.db")
        HostileLocationSettings(context).setEnabled(true)
        val graph = DataGraph(context)
        graph.database.openHelper.writableDatabase // force creation — should stay in memory
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertFalse(dbFile.exists())
        graph.database.close()
    }

    @Test
    fun enablingAfterExistingOnDiskDatabase_deletesThePreToggleFile() = runBlocking {
        HostileLocationSettings(context).setEnabled(false)
        // DataGraph picks memory vs disk once at construction; drop graphs from earlier tests.
        DataRuntime.invalidate()
        // Use the DataRuntime singleton — the instance SecurityWipe.closeAndDeleteDatabase reaches.
        DataRuntime.graph(context).database.openHelper.writableDatabase // force creation with real pre-toggle state
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertTrue("Precondition: on-disk DB must exist before toggling on", dbFile.exists())

        // Mirrors SecuritySettingsActivity's hostileLocationSwitch listener: close + delete
        // first, persist the flag second — never persist-then-forget-to-delete.
        SecurityWipe.closeAndDeleteDatabase(context)
        HostileLocationSettings(context).setEnabled(true)

        assertFalse("Enabling must delete the pre-toggle on-disk database file", dbFile.exists())

        // Stands in for the AppRestart.relaunch restart: a fresh graph, not the stale singleton.
        val rebuiltGraph = DataGraph(context)
        rebuiltGraph.database.openHelper.writableDatabase
        assertFalse(
            "Rebuilt DataGraph must be in-memory-only and must not recreate the deleted file",
            dbFile.exists(),
        )
        rebuiltGraph.database.close()
    }
}
