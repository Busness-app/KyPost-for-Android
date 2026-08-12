package org.kysecurity.mail.mail

import android.content.Context
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import org.kysecurity.mail.ScopedValue
import kotlinx.coroutines.runBlocking

private val Context.mailSyncDataStore by preferencesDataStore(name = "mail_sync_state")

private const val FULL_RESYNC_INTERVAL_MS = 24L * 60 * 60 * 1000

/**
 * Blocking (non-suspend) by design, matching [MailSource] and [RelayMailSource]'s own
 * synchronous style — callers already run on a background executor thread. Backed by
 * [MailCursorStore] in production; tests inject an in-memory fake instead.
 */
interface MailCursorProvider {
    /** Null means "no cursor yet for this subscriber+folder" — caller should send since=0. */
    fun cursor(subscriberId: String, folder: String): String?
    fun saveCursor(subscriberId: String, folder: String, cursor: String)
    /** True once a day (per subscriber+folder) or if a full resync has never been recorded —
     *  the documented self-heal for a missed removal notification (Mobile_Mail_Relay.md Part 5). */
    fun shouldForceFullResync(subscriberId: String, folder: String): Boolean
    fun recordFullResync(subscriberId: String, folder: String)
}

/**
 * Durable per-subscriber, per-folder delta-sync cursor for GET /api/inbox (Mobile_Mail_Relay.md
 * Part 5, v2), mirroring [org.kysecurity.mail.push.PushRepository]'s pull-cursor pattern exactly.
 * Scoped to subscriber+folder so re-pairing or switching mailboxes can't apply a stale/foreign
 * cursor. Cursors are opaque server-issued strings, not assumed to be numeric or ordered.
 */
class MailCursorStore(
    private val context: Context,
    private val nowProvider: () -> Long = { System.currentTimeMillis() },
) : MailCursorProvider {

    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    /**
     * Under Hostile Location Protection nothing about the user's mail may touch disk, and this
     * store's keys encode which folders exist and when each was last read. Held in memory instead,
     * matching [org.kysecurity.mail.push.PushRepository]'s in-memory push history — a cold process just
     * starts from since=0, which is correct, only less efficient.
     */
    private val inMemoryCursors = mutableMapOf<String, String>()
    private val inMemoryResyncAt = mutableMapOf<String, Long>()

    private fun inMemory(): Boolean = hostileLocationSettings.isEnabled()

    override fun cursor(subscriberId: String, folder: String): String? {
        if (inMemory()) {
            return synchronized(inMemoryCursors) { inMemoryCursors[memKey(subscriberId, folder)] }
                ?.takeIf { it.isNotBlank() }
        }
        return runBlocking { cursorValue(folder).get(subscriberId)?.takeIf { it.isNotBlank() } }
    }

    override fun saveCursor(subscriberId: String, folder: String, cursor: String) {
        if (cursor.isBlank()) return
        if (inMemory()) {
            synchronized(inMemoryCursors) { inMemoryCursors[memKey(subscriberId, folder)] = cursor }
            return
        }
        runBlocking { cursorValue(folder).set(subscriberId, cursor) }
    }

    override fun shouldForceFullResync(subscriberId: String, folder: String): Boolean {
        val lastAt = if (inMemory()) {
            synchronized(inMemoryResyncAt) { inMemoryResyncAt[memKey(subscriberId, folder)] }
        } else {
            runBlocking { resyncValue(folder).get(subscriberId) }
        }
        return lastAt == null || (nowProvider() - lastAt) >= FULL_RESYNC_INTERVAL_MS
    }

    override fun recordFullResync(subscriberId: String, folder: String) {
        if (inMemory()) {
            synchronized(inMemoryResyncAt) { inMemoryResyncAt[memKey(subscriberId, folder)] = nowProvider() }
            return
        }
        runBlocking { resyncValue(folder).set(subscriberId, nowProvider()) }
    }

    private fun memKey(subscriberId: String, folder: String) = "$subscriberId\u0000$folder"

    private fun cursorValue(folder: String) = ScopedValue(
        dataStore = context.mailSyncDataStore,
        scopeKey = stringPreferencesKey("inbox_cursor_scope_${folderKey(folder)}"),
        valueKey = stringPreferencesKey("inbox_cursor_value_${folderKey(folder)}"),
    )

    /**
     * Its **own** scope key, not the cursor's.
     *
     * [ScopedValue.set] writes the scope alongside its value, so sharing one key meant writing the
     * resync stamp re-stamped the scope over a *stale cursor* and re-authorised it for the new
     * subscriber — precisely the opposite of ScopedValue's stated guarantee that "a change of scope
     * reads back null instead of the previous scope's stale value". After re-pairing, a relay that
     * answered the first `/api/inbox` with a blank cursor (a supported case the repo's own tests
     * exercise) skipped `saveCursor` while `recordFullResync` re-stamped the scope, and the next
     * refresh 90 seconds later put the *previous* relay's cursor token on the wire to the new one.
     */
    private fun resyncValue(folder: String) = ScopedValue(
        dataStore = context.mailSyncDataStore,
        scopeKey = stringPreferencesKey("inbox_resync_scope_${folderKey(folder)}"),
        valueKey = longPreferencesKey("inbox_last_full_resync_${folderKey(folder)}"),
    )

    private companion object {
        /**
         * Hashes the folder into the key name instead of interpolating it, which fixes two things.
         *
         * Folder paths are unvalidated server strings, and the old scheme used one prefix that was
         * a prefix of the other (`inbox_cursor_` / `inbox_cursor_sub_`), so a folder named
         * `sub_INBOX` produced a key name identical to INBOX's scope marker — same name, same type,
         * same file, and `Preferences.Key` equality is on the name alone. That silently corrupted
         * both folders' cursors and could write the subscriber id where a cursor belonged.
         *
         * It also stopped the key names from spelling out the user's folder taxonomy (`Archive/
         * Legal/Asylum-Case`) in a plaintext DataStore. The prefixes are now non-prefixing, so no
         * hash value can collide across the two roles either.
         *
         * Changing the scheme abandons existing cursors, which costs exactly one full resync.
         */
        private fun folderKey(folder: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(folder.toByteArray(Charsets.UTF_8))
            return digest.take(12).joinToString("") { "%02x".format(it) }
        }
    }
}
