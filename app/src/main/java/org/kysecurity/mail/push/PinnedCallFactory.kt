package org.kysecurity.mail.push

import android.content.Context
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.pairingHttpClient
import okhttp3.Call
import okhttp3.Request
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Builds (and caches) a TLS-pinned [Call.Factory] from the stored TOFU pin, rebuilding only when
 * the pin actually changes — e.g. on re-pairing after a legitimate cert rotation. Returns null
 * (meaning: the caller should fall back to an unpinned client) until a pin has been captured, i.e.
 * before the very first successful pairing completes.
 *
 * The host now comes from the pin itself ([TlsPin.host]) rather than from the pairing's
 * `serverUrl`. The pin is captured from the *registration* URL's TLS handshake, so pinning it
 * against `serverUrl`'s host was only ever correct because the two usually happen to match — and
 * a pairing QR could make them differ, which pinned the wrong host's certificate and bricked every
 * subsequent request with an unrecoverable `SSLPeerUnverifiedException`.
 */
class PinnedCallFactoryProvider(
    private val tlsPinProvider: () -> TlsPin?,
    /** Passed through to [pairingHttpClient]; null keeps OkHttp's per-phase defaults. */
    private val callTimeoutMillis: Long? = null,
) : () -> Call.Factory? {
    /** The pin and the client built for it, published as ONE reference so a client can never be
     *  read against a pin it was not built for. Two separate `@Volatile` fields allowed exactly
     *  that under a concurrent re-pair. */
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

/**
 * Adapts a [PinnedCallFactoryProvider] into a plain [Call.Factory], for constructors that only
 * accept a fixed `Call.Factory` rather than a provider to re-check per call. Falls back to
 * [fallback] (plain, unpinned) until a pin exists, then starts pinning automatically the moment
 * one is captured, re-checked on every request rather than snapshotted once at construction time —
 * important since these clients are built once and live for the process's lifetime, well before
 * the first pairing (and thus the first TLS pin) may exist.
 *
 * **The fallback is only for [TlsPinState.NeverPaired].** This used to be `pinnedProvider() ?:
 * fallback`, which answered "we have no pin yet" and "our pin is gone" with the same unpinned
 * client — so a reset of the encrypted store (or any other loss of `KEY_TLS_PIN`) silently
 * downgraded every credential-bearing request to bare system-CA trust, permanently, with nothing
 * visible changing. [TlsPinState.Lost] now fails closed.
 */
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
            // A pin existed and no longer does. Falling back here is a silent downgrade of every
            // request carrying this device's credential, on the one event that most plausibly
            // means something went wrong with the encrypted store. Refuse instead — the user
            // re-pairs, which re-establishes a pin they can actually rely on.
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

/**
 * The one [PinnedOrFallbackCallFactory] shared by every client/graph that lives *outside*
 * [PushGraph] itself. [PushGraph]'s own internal clients cannot use this (it would recursively call
 * [PushRuntime.graph] while [PushGraph] is still being constructed) and instead wire a
 * [PinnedCallFactoryProvider] directly to their own repository instance — see
 * `PushGraph.pinnedOrFallbackCallFactory`.
 *
 * Safe to hold across an [org.kysecurity.mail.security.AppRestart]: the pin is resolved through
 * [PushRuntime.graph] on every request rather than captured, so a rebuilt graph — or a re-pairing
 * that replaces the pin — is picked up on the next call with nothing to invalidate here.
 */
private val sharedPinnedCallFactory = SingletonGraph<Call.Factory> { appContext ->
    PinnedOrFallbackCallFactory(
        pinnedProvider = PinnedCallFactoryProvider(
            tlsPinProvider = { PushRuntime.graph(appContext).repository.currentTlsPin() },
        ),
        pinStateProvider = { PushRuntime.graph(appContext).repository.tlsPinState() },
    )
}

fun pinnedPairingCallFactory(context: Context): Call.Factory = sharedPinnedCallFactory.get(context)
