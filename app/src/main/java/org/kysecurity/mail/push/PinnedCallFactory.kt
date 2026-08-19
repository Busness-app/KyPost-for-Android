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
            // downgrade from.
            TlsPinState.NeverPaired -> fallback.newCall(request)
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
}

/** A [Call] that fails with [cause] the moment it is executed or enqueued, so a refusal reaches
 *  callers through the same `IOException` path every other network failure does. */
private class FailedCall(private val request: Request, private val cause: java.io.IOException) : Call {
    @Volatile private var canceled = false
    override fun request(): Request = request
    override fun execute(): okhttp3.Response = throw cause
    override fun enqueue(responseCallback: okhttp3.Callback) = responseCallback.onFailure(this, cause)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = canceled
    override fun timeout(): okio.Timeout = okio.Timeout.NONE
    override fun clone(): Call = FailedCall(request, cause)
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
