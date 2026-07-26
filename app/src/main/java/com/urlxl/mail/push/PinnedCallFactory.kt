package com.urlxl.mail.push

import android.content.Context
import com.urlxl.mail.pairingHttpClient
import okhttp3.Call
import okhttp3.Request

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
) : () -> Call.Factory? {
    @Volatile private var cachedKey: TlsPin? = null
    @Volatile private var cachedClient: Call.Factory? = null

    override fun invoke(): Call.Factory? {
        val pin = tlsPinProvider() ?: return null
        cachedClient?.takeIf { cachedKey == pin }?.let { return it }
        return pairingHttpClient(pinnedSpkiSha256 = pin.spkiSha256, host = pin.host).also {
            cachedClient = it
            cachedKey = pin
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
 */
class PinnedOrFallbackCallFactory(
    private val pinnedProvider: () -> Call.Factory?,
    private val fallback: Call.Factory = pairingHttpClient(),
) : Call.Factory {
    override fun newCall(request: Request): Call = (pinnedProvider() ?: fallback).newCall(request)
}

/**
 * Convenience for wiring a [PinnedOrFallbackCallFactory] to [PushRuntime]'s shared repository —
 * for every client/graph that lives *outside* [PushGraph] itself. [PushGraph]'s own internal
 * clients cannot use this (it would recursively call [PushRuntime.graph] while [PushGraph] is
 * still being constructed) and instead wire a [PinnedCallFactoryProvider] directly to their own
 * repository instance — see `PushGraph.pinnedOrFallbackCallFactory`.
 */
fun pinnedPairingCallFactory(context: Context): Call.Factory {
    val appContext = context.applicationContext
    return PinnedOrFallbackCallFactory(
        PinnedCallFactoryProvider(
            tlsPinProvider = { PushRuntime.graph(appContext).repository.currentTlsPin() },
        ),
    )
}
