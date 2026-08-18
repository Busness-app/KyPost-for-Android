package org.kysecurity.mail.security

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
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

/**
 * Ceiling on the total plaintext held awaiting a read.
 *
 * [MAX_CONCURRENT_WRITES] bounds writer *threads*; nothing bounded the map they read from. Each
 * registration parks a whole attachment — up to the 25 MB relay download limit — in the heap for
 * [ATTACHMENT_TTL_MILLIS], and the TTL only matters if the process lives that long. Tapping a
 * handful of large attachments and backing out of each chooser (which never calls `take`) put
 * hundreds of megabytes of decrypted mail in the heap, on the one path whose entire premise is
 * that this plaintext is short-lived. Sized to comfortably hold several real attachments while
 * making "the user is opening things faster than viewers consume them" a refusal rather than an OOM.
 */
private const val MAX_PENDING_BYTES = 64L * 1024 * 1024

internal data class PendingAttachment(
    val bytes: ByteArray,
    val mimeType: String,
    /** What a viewer app shows the user. See [EphemeralAttachmentProvider.query]. */
    val displayName: String,
    val registeredAtMillis: Long = System.currentTimeMillis(),
)

/**
 * In-memory holder for attachment bytes awaiting a single ephemeral read, keyed by a one-time
 * token. Nothing here is ever written to disk — see [EphemeralAttachmentProvider], the
 * `ContentProvider` that serves these bytes to a viewer app.
 */
object EphemeralAttachmentBytes : org.kysecurity.mail.ProcessScopedState {
    private val pending = ConcurrentHashMap<String, PendingAttachment>()

    @Volatile
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
        // See [org.kysecurity.mail.ProcessScopedState]. This holder is the reason that registry exists:
        // it parks up to MAX_PENDING_BYTES of decrypted attachment plaintext in a process-scoped
        // object, and AppRestart.relaunch no longer kills the process — so a security wipe used to
        // run to completion, relaunch into the same JVM, and leave the plaintext readable in the
        // attacker's session. InMemoryPlaintext's own KDoc invited a future holder to register
        // here; this is that holder, and it did not.
        org.kysecurity.mail.ProcessState.register(this)
    }

    internal fun configure(authority: String) {
        this.authority = authority
    }

    /**
     * Drops and zeroes every held attachment. See [org.kysecurity.mail.ProcessScopedState].
     *
     * Zeroes rather than merely dropping, for the same reason [purgeExpired] does: until the
     * collector runs — and possibly after, if a buffer was promoted — this plaintext is readable
     * in a heap dump, and a wipe runs precisely when the device is presumed hostile.
     */
    override fun resetForNewSession() {
        pending.keys.toList().forEach { token ->
            pending.remove(token)?.let { Arrays.fill(it.bytes, 0) }
        }
    }

    /**
     * Parks [bytes] for a single ephemeral read, or returns null when doing so would push the
     * held-plaintext total past [MAX_PENDING_BYTES].
     */
    fun register(bytes: ByteArray, mimeType: String, displayName: String): Uri? {
        // Nothing may be parked under an unknown authority. [configure] runs from the provider's
        // attachInfo, and an empty authority produced `content:///token` — a malformed URI handed
        // to the chooser, resolving to nothing, with the plaintext left in the map until the
        // sweeper reached it. The caller already has a "cannot serve this" path; use it.
        val authority = this.authority
        if (authority.isBlank()) {
            android.util.Log.e("EphemeralAttachmentProvider", "Refusing to register before the provider is attached")
            return null
        }
        purgeExpired()
        val token = UUID.randomUUID().toString()
        synchronized(this) {
            val held = pending.values.sumOf { it.bytes.size.toLong() }
            if (held + bytes.size > MAX_PENDING_BYTES) return null
            pending[token] = PendingAttachment(bytes, mimeType, displayName)
        }
        return Uri.parse("content://$authority/$token")
    }

    internal fun take(token: String): PendingAttachment? = pending.remove(token)

    internal fun peekMimeType(token: String): String? = pending[token]?.mimeType

    /** Name and size for [EphemeralAttachmentProvider.query], without consuming the token. */
    internal fun peekMetadata(token: String): Pair<String, Long>? =
        pending[token]?.let { it.displayName to it.bytes.size.toLong() }

    /** Visible for tests, which need a deterministic sweep rather than waiting on the timer. */
    internal fun purgeExpired(nowMillis: Long = System.currentTimeMillis()) {
        val cutoff = nowMillis - ATTACHMENT_TTL_MILLIS
        val expired = pending.entries.filter { it.value.registeredAtMillis < cutoff }
        expired.forEach { entry ->
            // The removal's own return value decides ownership of the bytes, rather than zeroing
            // the array this iteration happened to see. `take()` can win the race between the
            // filter above and this line — a user tapping an attachment moments before its TTL —
            val removed = pending.remove(entry.key) ?: return@forEach
            // Overwrite rather than waiting for GC: until the collector runs (and possibly after,
            // if the buffer was promoted) this plaintext is readable in a heap dump.
            Arrays.fill(removed.bytes, 0)
        }
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
        // Checked BEFORE take(), which consumes the single-use token. `mode` used to be accepted
        // and discarded, so a viewer opening "rw" or "w" got a read-only pipe end, an
        // incomprehensible failure downstream, and a token that was already gone by the time it
        // retried. There is nothing here to write to: these bytes are read once and zeroed.
        if (mode != "r") {
            throw SecurityException("Ephemeral attachments are read-only; requested mode '$mode'")
        }
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

    /**
     * `OpenableColumns` only — enough for a viewer to name and size the attachment.
     *
     * Returning null here was not a neutral "there is no table". Well-behaved viewers query
     * `DISPLAY_NAME` and `SIZE` before opening a `content://` URI; several treat a null cursor as
     * "this URI does not exist" and refuse outright, and the ones that do not showed the user their
     * decrypted attachment under a bare UUID with no extension. This is the one path whose entire
     * purpose is that attachments open without ever touching disk, so it has to actually open.
     *
     * Deliberately does NOT consume the token — that is [openFile]'s job, and a metadata query is
     * not a read.
     */
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        val (name, size) = EphemeralAttachmentBytes.peekMetadata(tokenFrom(uri)) ?: return null
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = android.database.MatrixCursor(columns, 1)
        val row = arrayOfNulls<Any>(columns.size)
        columns.forEachIndexed { index, column ->
            row[index] = when (column) {
                OpenableColumns.DISPLAY_NAME -> name
                OpenableColumns.SIZE -> size
                else -> null
            }
        }
        cursor.addRow(row)
        return cursor
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
