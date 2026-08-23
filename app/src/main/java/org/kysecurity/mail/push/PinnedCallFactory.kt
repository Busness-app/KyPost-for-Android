package org.kysecurity.mail.push

import android.content.Context
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.pairingHttpClient
import okhttp3.Call
import okhttp3.Request
import javax.net.ssl.SSLPeerUnverifiedException

/** Caches a pinned [Call.Factory] from the stored TOFU pin; null until one is captured. */
class PinnedCallFactoryProvider(
    private val tlsPinProvider: () -> TlsPin?,
    /** Passed through to [pairingHttpClient]; null keeps OkHttp's per-phase defaults. */
    private val callTimeoutMillis: Long? = null,
) : () -> Call.Factory? {
    /** Pin and client published as ONE reference so a client is never read against another pin. */
    @Volatile private var cached: Pair<TlsPin, Call.Factory>? = null

    override fun invoke(): Call.Factory? {
        val pin = tlsPinProvider() ?: return null
        cached?.takeIf { it.first == pin }?.let { return it.second }
        // Synchronized, so a concurrent re-pair produces one client rather than one per caller.
        // Re-checked inside: another thread may have built it while this one waited.
        return synchronized(this) {
            cached?.takeIf { it.first == pin }?.second ?: run {
                val client = pairingHttpClient(
                    posture = PinPosture.Pinned(host = pin.host, spkiSha256 = pin.spkiSha256),
                    callTimeoutMillis = callTimeoutMillis,
                )
                cached = pin to client
                client
            }
        }
    }
}

/** Falls back to [fallback] only for [TlsPinState.NeverPaired]; [TlsPinState.Lost] fails closed. */
class PinnedOrFallbackCallFactory(
    private val pinnedProvider: () -> Call.Factory?,
    private val pinStateProvider: () -> TlsPinState,
    private val fallback: Call.Factory = pairingHttpClient(PinPosture.TofuWindow),
) : Call.Factory {
    override fun newCall(request: Request): Call {
        pinnedProvider()?.let { return it.newCall(request) }
        return when (pinStateProvider()) {
            // The legitimate TOFU window: nothing has ever been pinned, so there is nothing to
            // downgrade from. A pin carried in the pairing link narrows it to one key for the one
            // request that discloses the pairing token. Deliberately NOT consulted for
            // TlsPinState.Lost: a link cannot re-authorise a server whose stored pin is gone.
            TlsPinState.NeverPaired -> linkPinnedCall(request) ?: fallback.newCall(request)
            // A pin existed and no longer does: refuse rather than silently downgrade. Re-pair to fix.
            TlsPinState.Lost -> FailedCall(
                request,
                SSLPeerUnverifiedException(
                    "The stored TLS pin for this server is gone; re-pair this device before it will connect again.",
                ),
            )
            // Unreachable: pinnedProvider() returns non-null exactly when this is Pinned. Refusing
            // is still the right answer if that ever stops being true.
            is TlsPinState.Pinned -> FailedCall(
                request,
                SSLPeerUnverifiedException("TLS pin could not be applied"),
            )
        }
    }

    /** Null when the request carries no link pin, so the caller falls back to the TOFU window. */
    private fun linkPinnedCall(request: Request): Call? {
        val linkPin = request.tag(org.kysecurity.mail.LinkPin::class.java) ?: return null
        // Built for this call and dropped with it. These were cached, keyed by the pin, behind a
        // comment claiming the map was "bounded in practice" — it was keyed by whatever host and
        // pin a BROWSABLE pairing link supplied, so any app on the device could grow it without
        // ever completing a pairing. The saving was never real either: [pairingHttpClient] derives
        // from one shared base client, so this is a config wrapper over an already-shared
        // dispatcher and connection pool, in front of a call that is about to do a TLS handshake.
        val client = pairingHttpClient(
            PinPosture.Pinned(host = linkPin.host, spkiSha256 = setOf(linkPin.spkiSha256)),
        )
        return client.newCall(request)
    }
}

/** A [Call] that fails with [cause] the moment it is executed or enqueued, so a refusal reaches
 *  callers through the same `IOException` path every other network failure does. */
private class FailedCall(private val request: Request, private val cause: java.io.IOException) : Call {
    @Volatile private var canceled = false

    /** A [Call] is single-use. Reporting `isExecuted() == false` after a refusal would offer a
     *  spent call back to any retry or instrumentation that asks, which is the one question this
     *  flag exists to answer. */
    private val executed = java.util.concurrent.atomic.AtomicBoolean(false)

    override fun request(): Request = request

    override fun execute(): okhttp3.Response {
        markExecuted()
        throw cause
    }

    /** Delivered inline, unlike a real dispatch: the failure is known before any I/O, so there is
     *  nothing to wait for and no dispatcher of our own to hand it to. */
    override fun enqueue(responseCallback: okhttp3.Callback) {
        markExecuted()
        responseCallback.onFailure(this, cause)
    }

    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed.get()
    override fun isCanceled(): Boolean = canceled
    override fun timeout(): okio.Timeout = okio.Timeout.NONE
    override fun clone(): Call = FailedCall(request, cause)

    private fun markExecuted() = check(executed.compareAndSet(false, true)) { "Already Executed" }
}

/** Shared by every client outside [PushGraph]; its own clients would recurse building it. */
private val sharedPinnedCallFactory = SingletonGraph<Call.Factory> { appContext ->
    PinnedOrFallbackCallFactory(
        pinnedProvider = PinnedCallFactoryProvider(
            tlsPinProvider = { PushRuntime.graph(appContext).repository.currentTlsPin() },
        ),
        pinStateProvider = { PushRuntime.graph(appContext).repository.tlsPinState() },
    )
}

fun pinnedPairingCallFactory(context: Context): Call.Factory = sharedPinnedCallFactory.get(context)
