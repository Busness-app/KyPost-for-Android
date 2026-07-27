package com.urlxl.mail.security

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.IOException
import java.util.Arrays
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

// How long a registered-but-never-opened attachment's bytes may linger in the process heap. Short:
// this only bridges "user tapped View" to "the OS finished launching a viewer app", not a cache.
private const val ATTACHMENT_TTL_MILLIS = 60_000L
private const val SWEEP_INTERVAL_SECONDS = 15L

/**
 * Ceiling on *concurrent* pipe writes. One raw `Thread` per attachment was unbounded thread
 * creation driven by how fast the user can tap; a two-thread fixed pool replaced that with
 * head-of-line blocking, which is worse.
 *
 * A pipe holds 64 KB and `write()` blocks until the reader drains it, so a viewer app that opens
 * the descriptor and then stops reading — backgrounded, ANR'd, or sniffing only a MIME prefix —
 * parks its writer thread indefinitely. With a fixed pool of two and an unbounded queue, two such
 * viewers wedged every subsequent attachment open for the life of the process, with no timeout and
 * no error, on the one path whose entire purpose is that this is how you open an attachment under
 * Hostile Location Protection.
 *
 * The pool below pairs this cap with a [SynchronousQueue], so a write never waits behind a stalled
 * one: it either gets a thread immediately or is refused outright, and [EphemeralAttachmentProvider]
 * turns a refusal into an `IOException` the caller can see. Stalled writers still hold their thread
 * (nothing can safely interrupt a blocking write mid-stream without handing the viewer a truncated
 * file), but they can now only consume slots up to this bound.
 */
private const val MAX_CONCURRENT_WRITES = 8

/** How long an idle writer thread sticks around before being reclaimed. */
private const val WRITER_KEEP_ALIVE_SECONDS = 60L

internal data class PendingAttachment(
    val bytes: ByteArray,
    val mimeType: String,
    val registeredAtMillis: Long = System.currentTimeMillis(),
)

/**
 * In-memory holder for attachment bytes awaiting a single ephemeral read, keyed by a one-time
 * token. Nothing here is ever written to disk — see [EphemeralAttachmentProvider], the
 * `ContentProvider` that serves these bytes to a viewer app.
 */
object EphemeralAttachmentBytes {
    private val pending = ConcurrentHashMap<String, PendingAttachment>()
    private var authority: String = ""

    /**
     * Expiry runs on a timer, not lazily on the next [register].
     *
     * The lazy version only bounded the lifetime if another attachment was ever registered: view
     * one attachment, back out of the chooser so nothing calls [take], and those decrypted bytes
     * stayed in the heap for the life of the process. On the Hostile Location Protection path —
     * whose entire purpose is that attachment plaintext never persists — that is the failure the
     * feature exists to prevent, and the doc comment claiming it was bounded was simply wrong.
     */
    private val sweeper = Executors.newSingleThreadScheduledExecutor(daemonThreadFactory("ephemeral-attachment-sweeper"))

    /** See [MAX_CONCURRENT_WRITES]. `SynchronousQueue` is load-bearing: it has no capacity, so a
     *  submission that finds every thread busy is rejected immediately instead of queueing behind
     *  a writer that may never finish. */
    internal val writeExecutor: ThreadPoolExecutor = ThreadPoolExecutor(
        0,
        MAX_CONCURRENT_WRITES,
        WRITER_KEEP_ALIVE_SECONDS,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        daemonThreadFactory("ephemeral-attachment-writer"),
    )

    init {
        sweeper.scheduleWithFixedDelay(
            { runCatching { purgeExpired() } },
            SWEEP_INTERVAL_SECONDS,
            SWEEP_INTERVAL_SECONDS,
            TimeUnit.SECONDS,
        )
    }

    internal fun configure(authority: String) {
        this.authority = authority
    }

    fun register(bytes: ByteArray, mimeType: String): Uri {
        val token = UUID.randomUUID().toString()
        pending[token] = PendingAttachment(bytes, mimeType)
        return Uri.parse("content://$authority/$token")
    }

    internal fun take(token: String): PendingAttachment? = pending.remove(token)

    internal fun peekMimeType(token: String): String? = pending[token]?.mimeType

    /** Visible for tests, which need a deterministic sweep rather than waiting on the timer. */
    internal fun purgeExpired(nowMillis: Long = System.currentTimeMillis()) {
        val cutoff = nowMillis - ATTACHMENT_TTL_MILLIS
        val expired = pending.entries.filter { it.value.registeredAtMillis < cutoff }
        expired.forEach { entry ->
            // The removal's own return value decides ownership of the bytes, rather than zeroing
            // the array this iteration happened to see. `take()` can win the race between the
            // filter above and this line — a user tapping an attachment moments before its TTL —
            // and the old code then zeroed a buffer the provider's writer thread was already
            // streaming to a viewer app. The viewer received a file that trailed off into zeros,
            // with no error anywhere.
            val removed = pending.remove(entry.key) ?: return@forEach
            // Overwrite rather than waiting for GC: until the collector runs (and possibly after,
            // if the buffer was promoted) this plaintext is readable in a heap dump.
            Arrays.fill(removed.bytes, 0)
        }
    }

    /** Visible for tests. */
    internal fun clearForTest() {
        pending.keys.toList().forEach { pending.remove(it) }
    }

    private fun daemonThreadFactory(name: String) = ThreadFactory { runnable ->
        Thread(runnable, name).apply { isDaemon = true }
    }
}

/**
 * Serves attachment bytes registered via [EphemeralAttachmentBytes.register] through a pipe, never
 * a file. Each token is single-use: [EphemeralAttachmentBytes.take] removes it from memory the
 * moment this provider starts serving it.
 */
class EphemeralAttachmentProvider : ContentProvider() {
    override fun attachInfo(context: android.content.Context, info: ProviderInfo) {
        super.attachInfo(context, info)
        EphemeralAttachmentBytes.configure(info.authority)
    }

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = EphemeralAttachmentBytes.peekMimeType(tokenFrom(uri))

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val attachment = EphemeralAttachmentBytes.take(tokenFrom(uri))
            ?: throw IOException("Attachment already consumed or unknown: $uri")
        val pipe = ParcelFileDescriptor.createReliablePipe()
        val readSide = pipe[0]
        val writeSide = pipe[1]
        try {
            EphemeralAttachmentBytes.writeExecutor.execute {
                try {
                    ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { it.write(attachment.bytes) }
                } catch (e: Exception) {
                    // Expected/benign, not a bug: the viewer app can close its read side before this
                    // finishes writing (user backs out of the app chooser, the viewer only reads a
                    // MIME-sniffing prefix, etc.), which surfaces here as a broken-pipe IOException.
                    android.util.Log.w(
                        "EphemeralAttachmentProvider",
                        "Attachment write aborted (reader likely closed early)",
                        e,
                    )
                } finally {
                    Arrays.fill(attachment.bytes, 0)
                }
            }
        } catch (e: RejectedExecutionException) {
            // Every writer slot is held by a viewer that stopped reading (see MAX_CONCURRENT_WRITES).
            // Fail loudly and clean up rather than queueing: an attachment that never opens and
            // never errors is indistinguishable from a hung app, and the plaintext must not be left
            // sitting in the heap behind a write that will never run.
            Arrays.fill(attachment.bytes, 0)
            runCatching { writeSide.close() }
            runCatching { readSide.close() }
            throw IOException("Too many attachment views are still open; close one and retry", e)
        }
        return readSide
    }

    private fun tokenFrom(uri: Uri): String = uri.lastPathSegment.orEmpty()

    // Not a real data table — attachments are single-use byte streams, not queryable rows.
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
