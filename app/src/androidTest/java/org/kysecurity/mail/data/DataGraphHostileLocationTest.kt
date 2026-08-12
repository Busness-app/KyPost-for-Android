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

    /**
     * Reproduces finding C1 (2026-07-22 spec's final-review fix round): the two tests above only
     * prove *in-memory Room never creates a file* — they say nothing about whether turning
     * Hostile Location Protection *on* actually deletes a database file that already existed from
     * before the toggle. This exercises the exact sequence
     * [org.kysecurity.mail.security.SecuritySettingsActivity]'s `hostileLocationSwitch` listener runs
     * in production (`SecurityWipe.closeAndDeleteDatabase` then `HostileLocationSettings.setEnabled(true)`,
     * then — standing in for the process restart `AppRestart.relaunch` would otherwise do — a
     * fresh `DataGraph(context)` construction) and asserts nothing from before the toggle
     * survives: the old file is gone, and the rebuilt graph is in-memory-only.
     */
    @Test
    fun enablingAfterExistingOnDiskDatabase_deletesThePreToggleFile() = runBlocking {
        HostileLocationSettings(context).setEnabled(false)
        // DataRuntime is a process-lifetime singleton (see SingletonGraph) — using it here (not
        // a standalone `DataGraph(context)`, unlike the two tests above) matters: it's the same
        // instance production code (and SecurityWipe.closeAndDeleteDatabase below) reaches via
        // DataRuntime.graph(context) elsewhere in the app, so this reproduces the real call chain
        // rather than a disconnected copy of it.
        DataRuntime.graph(context).database.openHelper.writableDatabase // force creation with real pre-toggle state
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertTrue("Precondition: on-disk DB must exist before toggling on", dbFile.exists())

        // Mirrors SecuritySettingsActivity's hostileLocationSwitch listener: close + delete
        // first, persist the flag second — never persist-then-forget-to-delete.
        SecurityWipe.closeAndDeleteDatabase(context)
        HostileLocationSettings(context).setEnabled(true)

        assertFalse("Enabling must delete the pre-toggle on-disk database file", dbFile.exists())

        // Standing in for the process restart AppRestart.relaunch would otherwise do: a fresh,
        // independent DataGraph (not through the now-stale DataRuntime singleton — see
        // SecurityWipe.wipeAndResetApp's caller contract) must come up in-memory and must not
        // resurrect the deleted file.
        val rebuiltGraph = DataGraph(context)
        rebuiltGraph.database.openHelper.writableDatabase
        assertFalse(
            "Rebuilt DataGraph must be in-memory-only and must not recreate the deleted file",
            dbFile.exists(),
        )
        rebuiltGraph.database.close()
    }
}
