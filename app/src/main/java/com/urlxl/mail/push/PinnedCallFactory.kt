package com.urlxl.mail.push

import android.content.Context
import com.urlxl.mail.SingletonGraph
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
        val client = pairingHttpClient(
            pinnedSpkiSha256 = pin.spkiSha256,
            host = pin.host,
            callTimeoutMillis = callTimeoutMillis,
        )
        cached = pin to client
        return client
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
 * The one [PinnedOrFallbackCallFactory] shared by every client/graph that lives *outside*
 * [PushGraph] itself. [PushGraph]'s own internal clients cannot use this (it would recursively call
 * [PushRuntime.graph] while [PushGraph] is still being constructed) and instead wire a
 * [PinnedCallFactoryProvider] directly to their own repository instance — see
 * `PushGraph.pinnedOrFallbackCallFactory`.
 *
 * Process-scoped, because this used to build a brand-new one — and with it a brand-new
 * [pairingHttpClient] for the unpinned fallback, plus a fresh pinned client the moment a pin
 * existed — on **every call**. It is invoked from default-argument positions that re-evaluate per
 * call ([com.urlxl.mail.pgp.hasPgpIdentity]) and per screen
 * ([com.urlxl.mail.ComposePgpController.from], twice), so opening the contacts list or the composer
 * repeatedly accumulated `OkHttpClient`s, each holding its own `ConnectionPool` of idle keep-alive
 * sockets for five minutes plus a cleanup thread. Sharing one instance also means TLS sessions and
 * connections are actually reused across these clients, which was the point of [PushGraph] holding
 * a single factory in the first place.
 *
 * Safe to hold across an [com.urlxl.mail.security.AppRestart]: the pin is resolved through
 * [PushRuntime.graph] on every request rather than captured, so a rebuilt graph — or a re-pairing
 * that replaces the pin — is picked up on the next call with nothing to invalidate here.
 */
private val sharedPinnedCallFactory = SingletonGraph<Call.Factory> { appContext ->
    PinnedOrFallbackCallFactory(
        PinnedCallFactoryProvider(
            tlsPinProvider = { PushRuntime.graph(appContext).repository.currentTlsPin() },
        ),
    )
}

fun pinnedPairingCallFactory(context: Context): Call.Factory = sharedPinnedCallFactory.get(context)
