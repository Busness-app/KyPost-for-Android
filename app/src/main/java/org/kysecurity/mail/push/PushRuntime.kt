package org.kysecurity.mail.push

import android.content.Context
import org.kysecurity.mail.SingletonGraph
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

    /**
     * The single [MfaChallengeTracker] for the process.
     */
    val mfaChallengeTracker = MfaChallengeTracker(appContext)

    // Every credential-bearing client below shares this one pinned-or-fallback factory rather
    // than defaulting to the plain unpinned `pairingHttpClient()` — see the 2026-07-22
    // security-hardening spec's final-review fix round, finding C2. Wired directly to this
    // graph's own [repository] (not via [PushRuntime.graph], which would recursively construct
    // this same [PushGraph] instance mid-construction) — falls back to unpinned only while no pin
    // has EVER been captured (i.e. before the first successful pairing), then pins from the next
    // request onward. A pin that existed and is now gone fails closed; see [TlsPinState].
    private val pinnedOrFallbackCallFactory: Call.Factory = PinnedOrFallbackCallFactory(
        pinnedProvider = PinnedCallFactoryProvider(tlsPinProvider = { repository.currentTlsPin() }),
        pinStateProvider = { repository.tlsPinState() },
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

    /**
     * Deregistration gets its own factory purely for the hard call timeout.
     *
     * Both callers treat a failed deregister as non-fatal and clear local state regardless
     * ([PushRepository.unpairDevice]), and [org.kysecurity.mail.security.SecurityWipe] runs it while an
     * attacker may be holding the device — where it must not be able to hold the wipe open for
     * OkHttp's default connect-plus-read budget. The wipe wrapped it in `withTimeoutOrNull`, which
     * cannot interrupt a thread blocked in a socket read; OkHttp cancelling its own call can. The
     * request is a `{}` POST with a one-field response, so this ceiling cannot cut a real one short.
     */
    val deregisterClient = DeregisterClient(
        callFactory = PinnedOrFallbackCallFactory(
            pinnedProvider = PinnedCallFactoryProvider(
                tlsPinProvider = { repository.currentTlsPin() },
                callTimeoutMillis = DEREGISTER_CALL_TIMEOUT_MS,
            ),
            pinStateProvider = { repository.tlsPinState() },
            fallback = org.kysecurity.mail.pairingHttpClient(callTimeoutMillis = DEREGISTER_CALL_TIMEOUT_MS),
        ),
    )

    private companion object {
        const val DEREGISTER_CALL_TIMEOUT_MS = 3_000L
    }
}

object PushRuntime {
    private val holder = SingletonGraph(::PushGraph)

    fun graph(context: Context): PushGraph = holder.get(context)

    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}

