package com.urlxl.mail.mail

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.urlxl.mail.ScopedValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/**
 * Regression test for [MailCursorStore]'s scope-key separation.
 *
 * `cursorValue(folder)` and `resyncValue(folder)` are two [ScopedValue]s over the same DataStore.
 * They used to share one scopeKey, and [ScopedValue.set] writes the scope alongside its own value —
 * so writing the resync stamp re-stamped the scope over a *stale cursor* and re-authorised it for a
 * new subscriber, which is exactly the opposite of ScopedValue's stated contract. After re-pairing,
 * a relay that answered the first `/api/inbox` with a blank cursor (a supported case
 * `RelayMailSourceTest.nonDeltaLegacyResponse_stillParsesAsFullSnapshot` exercises) made the client
 * put the *previous* relay's cursor token on the wire to the new one.
 */
class Run4ScopedCursorProbeTest {

    private fun store(dir: File) = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        produceFile = { File(dir, "mail_sync_state.preferences_pb") },
    )

    @Test
    fun recordFullResyncForANewSubscriber_doesNotReAuthorisePreviousSubscribersCursor(): Unit = runBlocking {
        val dir = File(System.getProperty("java.io.tmpdir"), "run4-cursor-${System.nanoTime()}")
        dir.mkdirs()
        val ds = store(dir)

        // MailCursorStore.cursorValue("INBOX") / resyncValue("INBOX") — now separate scope keys.
        val hash = "8b7df143d91c716ecfa5"
        val cursorValue = ScopedValue(
            ds,
            stringPreferencesKey("inbox_cursor_scope_$hash"),
            stringPreferencesKey("inbox_cursor_value_$hash"),
        )
        val resyncValue = ScopedValue(
            ds,
            stringPreferencesKey("inbox_resync_scope_$hash"),
            longPreferencesKey("inbox_last_full_resync_$hash"),
        )

        // Subscriber A, paired to relay S1, syncs INBOX and stores its cursor.
        cursorValue.set("subscriber-A", "c123-from-relay-S1")
        resyncValue.set("subscriber-A", 1_000L)

        // User re-pairs as subscriber B against a different relay.
        assertNull("precondition: B cannot read A's cursor", cursorValue.get("subscriber-B"))
        assertNull("precondition: B cannot read A's resync stamp", resyncValue.get("subscriber-B"))

        // First fetch as B: forced full resync (since=0). The relay answers with a BLANK cursor, so
        // saveCursor is skipped and only recordFullResync runs.
        resyncValue.set("subscriber-B", 2_000L)

        // Second fetch as B: the cursor must STILL be out of scope, so `since` starts from scratch
        // rather than carrying the previous relay's opaque token across an account boundary.
        assertNull(
            "subscriber B must not be able to read subscriber A's cursor",
            cursorValue.get("subscriber-B"),
        )
        // A's own values are untouched and still readable by A.
        assertEquals("c123-from-relay-S1", cursorValue.get("subscriber-A"))

        dir.deleteRecursively()
    }
}
