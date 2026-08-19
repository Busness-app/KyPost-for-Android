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

/** Capped so a stalled viewer cannot wedge later opens; pairs with the pool's SynchronousQueue. */
private const val MAX_CONCURRENT_WRITES = 8

/** How long an idle writer thread sticks around before being reclaimed. */
private const val WRITER_KEEP_ALIVE_SECONDS = 60L

/** Bounds retained plaintext; sized in MemoryBudget alongside the app's other heap ceilings. */
private const val MAX_PENDING_BYTES = org.kysecurity.mail.MemoryBudget.PENDING_ATTACHMENT_BYTES

/** Not a data class: identity equals over [bytes]. Enforced by `SourceRulesTest`.
 *
 *  [readers] and [revoked] are the refcount. Both are only ever touched while holding
 *  [EphemeralAttachmentBytes]'s monitor — see [EphemeralAttachmentBytes.acquire]. */
internal class PendingAttachment(
    val bytes: ByteArray,
    val mimeType: String,
    val displayName: String,
    val registeredAtMillis: Long = System.currentTimeMillis(),
) {
    var readers: Int = 0
    var revoked: Boolean = false
}

/** Attachment bytes awaiting a single ephemeral read; nothing here is ever written to disk. */
object EphemeralAttachmentBytes : org.kysecurity.mail.ProcessScopedState {
    private val pending = ConcurrentHashMap<String, PendingAttachment>()

    @Volatile
    private var authority: String = ""

    /** Expiry runs on a timer: a lazy sweep leaves bytes resident if nothing else registers. */
    private val sweeper = Executors.newSingleThreadScheduledExecutor(daemonThreadFactory("ephemeral-attachment-sweeper"))

    /** `SynchronousQueue` is load-bearing: with no free thread a write is refused, not queued. */
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
        // Registered because relaunch no longer kills the process holding this plaintext.
        org.kysecurity.mail.ProcessState.register(this)
    }

    internal fun configure(authority: String) {
        this.authority = authority
    }

    /** Zeroes rather than merely dropping: dropped plaintext stays readable in a heap dump. */
    override fun resetForNewSession() = synchronized(this) {
        pending.keys.toList().forEach { revoke(it) }
    }

    /** Takes ownership of [bytes] on every path, refusals included; callers must not reuse it. */
    fun register(bytes: ByteArray, mimeType: String, displayName: String): Uri? {
        // Nothing may be parked under an unknown authority; [configure] runs from attachInfo.
        val authority = this.authority
        if (authority.isBlank()) {
            android.util.Log.e("EphemeralAttachmentProvider", "Refusing to register before the provider is attached")
            Arrays.fill(bytes, 0)
            return null
        }
        val token = UUID.randomUUID().toString()
        // The budget scan and every mutation share this monitor (reentrantly, via purgeExpired):
        // summing a map two other threads were draining made `held` a number that was never true.
        synchronized(this) {
            purgeExpired()
            val held = pending.values.sumOf { it.bytes.size.toLong() }
            if (held + bytes.size > MAX_PENDING_BYTES) {
                Arrays.fill(bytes, 0)
                return null
            }
            pending[token] = PendingAttachment(bytes, mimeType, displayName)
        }
        return Uri.parse("content://$authority/$token")
    }

    /** Revokes the capability and zeroes as soon as it is safe to.
     *
     *  Immediately when nobody is reading, and otherwise at the last [release] — never while a
     *  writer still holds the array. `peek` hands the SAME reference to every concurrent opener,
     *  so an unconditional fill here would hand a reader mid-`write()` a half-zeroed file and no
     *  error. Returns whether a registration was actually removed. */
    internal fun revoke(token: String): Boolean = synchronized(this) {
        val removed = pending.remove(token) ?: return false
        removed.revoked = true
        if (removed.readers == 0) Arrays.fill(removed.bytes, 0)
        true
    }

    /** Claims a read. The bytes stay claimable while the token lives, because a viewer that probes
     *  for the type or size before reading must not consume its own attachment — but every claim
     *  is now counted, so the bytes can be zeroed at the LAST release rather than at the TTL. */
    internal fun acquire(token: String): PendingAttachment? = synchronized(this) {
        pending[token]?.also { it.readers++ }
    }

    /** Zeroes when this was the last reader of something already revoked or swept. */
    internal fun release(attachment: PendingAttachment): Unit = synchronized(this) {
        attachment.readers--
        if (attachment.readers <= 0 && attachment.revoked) Arrays.fill(attachment.bytes, 0)
    }

    /** Metadata only, no claim. */
    internal fun peek(token: String): PendingAttachment? = pending[token]

    internal fun peekMimeType(token: String): String? = pending[token]?.mimeType

    /** Name and size for [EphemeralAttachmentProvider.query], without consuming the token. */
    internal fun peekMetadata(token: String): Pair<String, Long>? =
        pending[token]?.let { it.displayName to it.bytes.size.toLong() }

    /** Visible for tests, which need a deterministic sweep rather than waiting on the timer. */
    internal fun purgeExpired(nowMillis: Long = System.currentTimeMillis()): Unit = synchronized(this) {
        val cutoff = nowMillis - ATTACHMENT_TTL_MILLIS
        // Overwrite rather than waiting for GC: until the collector runs (and possibly after, if
        // the buffer was promoted) this plaintext is readable in a heap dump. `revoke` defers the
        // fill to the last reader when one is still streaming, and does it inline when none is.
        pending.entries.filter { it.value.registeredAtMillis < cutoff }
            .map { it.key }
            .forEach { revoke(it) }
    }

    private fun daemonThreadFactory(name: String) = ThreadFactory { runnable ->
        Thread(runnable, name).apply { isDaemon = true }
    }
}

/** Serves registered bytes through a pipe, never a file.
 *
 *  A token is NOT single-use: a viewer that probes for type or size before reading must be able to
 *  reopen it, and consuming on first open broke every one of those. It stays readable until the
 *  TTL sweep reaps it, so any holder of the URI may open it any number of times inside that
 *  window. What bounds the PLAINTEXT is narrower than that window — every open is refcounted, and
 *  the bytes are zeroed at the last release once revoked or swept, not left to the collector. */
class EphemeralAttachmentProvider : ContentProvider() {
    override fun attachInfo(context: android.content.Context, info: ProviderInfo) {
        super.attachInfo(context, info)
        EphemeralAttachmentBytes.configure(info.authority)
    }

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = EphemeralAttachmentBytes.peekMimeType(tokenFrom(uri))

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        // Checked before anything is served.
        if (mode != "r") {
            throw SecurityException("Ephemeral attachments are read-only; requested mode '$mode'")
        }
        val token = tokenFrom(uri)
        // acquire, not take: the token survives so a probe-then-reopen viewer still works, but the
        // read is COUNTED, so the bytes have a known last reader to be zeroed after.
        val attachment = EphemeralAttachmentBytes.acquire(token)
            ?: throw IOException("Attachment expired or unknown: $uri")
        val pipe = ParcelFileDescriptor.createReliablePipe()
        val readSide = pipe[0]
        val writeSide = pipe[1]
        try {
            EphemeralAttachmentBytes.writeExecutor.execute {
                try {
                    ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { it.write(attachment.bytes) }
                } catch (e: Exception) {
                    // Benign: the viewer can close its read side early, giving a broken pipe.
                    android.util.Log.w(
                        "EphemeralAttachmentProvider",
                        "Attachment write aborted (reader likely closed early)",
                        e,
                    )
                } finally {
                    // Zeroes here when this was the last reader of a revoked or swept attachment,
                    // and does nothing while another writer still holds the same array.
                    EphemeralAttachmentBytes.release(attachment)
                }
            }
        } catch (e: RejectedExecutionException) {
            EphemeralAttachmentBytes.release(attachment)
            // Every writer slot is held by a stalled viewer; fail loudly rather than queue. The
            // capability is revoked now rather than waiting out its TTL, and `revoke` decides when
            // the array may be filled: immediately if this rejection left no reader, otherwise at
            // the last release. An unconditional fill here — which is what this used to do — could
            // hand one of the eight writers the rejection proves are running a half-zeroed file.
            EphemeralAttachmentBytes.revoke(token)
            runCatching { writeSide.close() }
            runCatching { readSide.close() }
            throw IOException("Too many attachment views are still open; close one and retry", e)
        }
        return readSide
    }

    private fun tokenFrom(uri: Uri): String = uri.lastPathSegment.orEmpty()

    /** Must not return null (viewers refuse the URI) and must not consume the token. */
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
