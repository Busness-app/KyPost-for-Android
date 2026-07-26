package com.urlxl.mail.push

import android.content.Context
import com.urlxl.mail.SingletonGraph
import okhttp3.Call

class PushGraph(context: Context) {
    private val appContext = context.applicationContext

    /**
     * The single [SecurePairingStore] for the process. It owns a StateFlow of the current pairing,
     * and four ad-hoc instances of it used to exist across the app — each with its own copy of that
     * flow, so a write through one was invisible to collectors on another and `PushRepository`
     * could keep reporting a pairing that had already been cleared or re-wrapped.
     */
    val securePairingStore = SecurePairingStore(appContext)

    val repository = PushRepository(appContext, securePairingStore)

    // Every credential-bearing client below shares this one pinned-or-fallback factory rather
    // than defaulting to the plain unpinned `pairingHttpClient()` — see the 2026-07-22
    // security-hardening spec's final-review fix round, finding C2. Wired directly to this
    // graph's own [repository] (not via [PushRuntime.graph], which would recursively construct
    // this same [PushGraph] instance mid-construction) — falls back to unpinned automatically
    // until a TLS pin exists (i.e. before the first successful pairing), then pins from the next
    // request onward.
    private val pinnedOrFallbackCallFactory: Call.Factory = PinnedOrFallbackCallFactory(
        PinnedCallFactoryProvider(tlsPinProvider = { repository.currentTlsPin() }),
    )

    val pullCoordinator = PullSyncCoordinator(
        appContext = appContext,
        repository = repository,
        pullClient = PullNotificationClient(callFactory = pinnedOrFallbackCallFactory),
    )
    val syncCoordinator = PushSyncCoordinator(
        repository = repository,
        // First pairing itself stays correctly TOFU-unpinned (no pin exists yet, so this falls
        // back to plain `pairingHttpClient()`); every resync afterward automatically pins once
        // the pairing call above has captured one.
        registrationClient = NativeRegistrationClient(callFactory = pinnedOrFallbackCallFactory),
    )
    val mfaResponseClient = MfaResponseClient(callFactory = pinnedOrFallbackCallFactory)
    val deregisterClient = DeregisterClient(callFactory = pinnedOrFallbackCallFactory)
}

object PushRuntime {
    private val holder = SingletonGraph(::PushGraph)

    fun graph(context: Context): PushGraph = holder.get(context)

    /** See [com.urlxl.mail.SingletonGraph.invalidate] — used by
     *  [com.urlxl.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}

