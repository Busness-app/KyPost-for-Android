package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.data.EmailDao
import org.kysecurity.mail.data.EmailEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** In-memory fake implementing the (Room-generated-at-build-time) [EmailDao] interface directly,
 *  matching this repo's hand-rolled-fake test style rather than a mocking framework or Robolectric. */
private class FakeEmailDao : EmailDao {
    val rows = linkedMapOf<String, EmailEntity>()

    override fun getByFolder(folder: String): List<EmailEntity> = rows.values.filter { it.folder == folder }
    override fun upsertAll(emails: List<EmailEntity>) { emails.forEach { rows[it.messageId] = it } }
    override fun updateStatus(id: String, status: String) { rows[id]?.let { rows[id] = it.copy(status = status) } }
    override fun updateFolder(id: String, folder: String) { rows[id]?.let { rows[id] = it.copy(folder = folder) } }
    override fun deleteById(id: String) { rows.remove(id) }
    override fun clearAll() { rows.clear() }
    override fun getBody(id: String): String? = rows[id]?.body
    override fun getById(id: String): EmailEntity? = rows[id]
    override fun pruneStaleInFolder(folder: String, keepIds: List<String>) {
        val keep = keepIds.toSet()
        rows.values.filter { it.folder == folder && it.messageId !in keep }.forEach { rows.remove(it.messageId) }
    }

    /** Mirrors the real query's predicate. The authority on the SQL itself is
     *  `EmailDaoClearDecryptedTest`, which runs it against a real Room database. */
    override fun clearServerDecryptedBodies(): Int {
        val hits = rows.values.filter { it.pgpEncrypted && !it.body.isNullOrEmpty() }
        hits.forEach { rows[it.messageId] = it.copy(body = "", preview = "") }
        return hits.size
    }
}

private fun email(id: String, body: String? = "body-$id", status: String = "unread") = Email(
    id = id,
    subject = "Subject $id",
    sender = "sender@example.com",
    preview = body.orEmpty(),
    body = body,
    status = status,
    sourceMode = "relay",
)

class MailRepositoryTest {

    @Test
    fun nonDeltaResult_replacesFolderSnapshotWholesale() {
        val dao = FakeEmailDao()
        dao.rows["stale"] = EmailEntity(messageId = "stale", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(tabs = listOf("Work"), messages = listOf(email("m1")), isDelta = false)
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("m1"), dao.rows.keys)
    }

    /**
     * The self-heal. A since=0 fetch returns the server's whole window, but an older relay labels
     * it `delta: true`, so pruning used to be skipped and a removal the device never received (its
     * one-shot `removed` notification went to another poller, or to a response that never arrived)
     * stayed in the inbox forever. Mail deleted on the web is exactly that case.
     */
    @Test
    fun fullWindowDeltaResult_prunesIdsAbsentFromTheResponse() {
        val dao = FakeEmailDao()
        dao.rows["deleted-on-web"] =
            EmailEntity(messageId = "deleted-on-web", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1")),
            isDelta = true,
            isFullWindow = true,
            removedMessageIds = emptyList(),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("m1"), dao.rows.keys)
    }

    /** Pruning on a full window must not cost us the bodies of entries the window reports as
     *  `updated` — those entries never carry one, so the merge still has to win. */
    @Test
    fun fullWindowDeltaResult_prunesButPreservesCachedBodyOfUpdatedEntries() {
        val dao = FakeEmailDao()
        dao.rows["m1"] = EmailEntity(
            messageId = "m1", folder = "INBOX", sender = "x", subject = "old",
            body = "cached-body", preview = "cached-preview", sourceMode = "relay",
        )
        dao.rows["gone"] =
            EmailEntity(messageId = "gone", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = true,
            isFullWindow = true,
            updatedMessageIds = setOf("m1"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("m1"), dao.rows.keys)
        assertEquals("cached-body", dao.rows["m1"]?.body)
        assertEquals("cached-preview", dao.rows["m1"]?.preview)
    }

    /** A cursor-based (partial) delta must keep pruning to itself — it only ever describes what
     *  changed, so anything it doesn't mention is still legitimately in the mailbox. */
    @Test
    fun partialDeltaResult_doesNotPruneUnmentionedRows() {
        val dao = FakeEmailDao()
        dao.rows["untouched"] =
            EmailEntity(messageId = "untouched", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(tabs = emptyList(), messages = listOf(email("m1")), isDelta = true)
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("untouched", "m1"), dao.rows.keys)
    }

    @Test
    fun deltaResult_insertsNewEntries() {
        val dao = FakeEmailDao()

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m1", body = "hello")),
            isDelta = true,
            updatedMessageIds = emptySet(),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("hello", dao.rows["m1"]?.body)
    }

    @Test
    fun deltaResult_mergesUpdatedEntry_preservingCachedBodyAndPreview() {
        val dao = FakeEmailDao()
        dao.rows["m2"] = EmailEntity(
            messageId = "m2", folder = "INBOX", sender = "old@example.com", subject = "Old subject",
            preview = "cached preview", body = "cached full body", status = "unread", sourceMode = "relay",
        )

        // An "updated" entry never carries a body (Mobile_Mail_Relay.md Part 5) — only status changed.
        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        val merged = dao.rows.getValue("m2")
        assertEquals("cached full body", merged.body)
        assertEquals("cached preview", merged.preview)
        assertEquals("read", merged.status)
    }

    /**
     * An "updated" delta entry never carries a body. With no local row there is nothing to merge
     * into, and storing the entry anyway created a row whose empty body was indistinguishable from a
     * client-protected message — so the detail view asserted "this message is end-to-end encrypted"
     * about mail the server had decrypted and previously shown. Skipping it is correct: we do not
     * have this message, and a metadata-only delta is not a delivery of it. The forced daily full
     * snapshot brings it in with its body.
     */
    @Test
    fun deltaResult_updatedEntryWithNoLocalCache_isSkippedRatherThanStoredBodyless() {
        val dao = FakeEmailDao()

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertNull(dao.rows["m2"])
    }

    @Test
    fun deltaResult_updatedEntryWithLocalCache_mergesPreservingBody() {
        val dao = FakeEmailDao()
        dao.rows["m2"] = EmailEntity(
            messageId = "m2",
            folder = "INBOX",
            sender = "x",
            subject = "x",
            sourceMode = "relay",
            body = "<p>cached</p>",
            status = "unread",
        )

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("<p>cached</p>", dao.rows.getValue("m2").body)
        assertEquals("read", dao.rows.getValue("m2").status)
    }

    @Test
    fun deltaResult_deletesRemovedIds() {
        val dao = FakeEmailDao()
        dao.rows["m3"] = EmailEntity(messageId = "m3", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(tabs = emptyList(), messages = emptyList(), isDelta = true, removedMessageIds = listOf("m3"))
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun deltaResult_mixOfNewUpdatedAndRemoved_allApplyTogether() {
        val dao = FakeEmailDao()
        dao.rows["m2"] = EmailEntity(
            messageId = "m2", folder = "INBOX", sender = "x", subject = "x",
            body = "cached body", preview = "cached preview", sourceMode = "relay",
        )
        dao.rows["m3"] = EmailEntity(messageId = "m3", folder = "INBOX", sender = "x", subject = "x", sourceMode = "relay")

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m1", body = "new body"), email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
            removedMessageIds = listOf("m3"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("m1", "m2"), dao.rows.keys)
        assertEquals("new body", dao.rows.getValue("m1").body)
        assertEquals("cached body", dao.rows.getValue("m2").body)
    }
}
