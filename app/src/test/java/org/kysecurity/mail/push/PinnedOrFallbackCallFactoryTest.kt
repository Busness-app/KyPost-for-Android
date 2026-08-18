package org.kysecurity.mail.push

import okhttp3.Call
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * The distinction this class exists for: "no pin yet" and "the pin is gone" are different states.
 *
 * The implementation this replaces was `pinnedProvider() ?: fallback`, which answered both with an
 * unpinned client. Every request from this app carries `X-Kypost-Device-Secret`, so the second case
 * was a permanent, silent downgrade to bare system-CA trust — triggered by anything that lost the
 * pin, most plausibly a reset of the encrypted store that holds it.
 */
class PinnedOrFallbackCallFactoryTest {

    private val request = Request.Builder().url("https://relay.example/api/inbox").build()

    private class RecordingFactory : Call.Factory {
        var calls = 0
        override fun newCall(request: Request): Call {
            calls++
            return NoopCall(request)
        }
    }

    private class NoopCall(private val request: Request) : Call {
        override fun request() = request
        override fun execute(): Response = throw UnsupportedOperationException()
        override fun enqueue(responseCallback: okhttp3.Callback) = Unit
        override fun cancel() = Unit
        override fun isExecuted() = false
        override fun isCanceled() = false
        override fun timeout(): okio.Timeout = okio.Timeout.NONE
        override fun clone(): Call = NoopCall(request)
    }

    @Test
    fun usesThePinnedClientWhenAPinExists() {
        val pinned = RecordingFactory()
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { pinned },
            pinStateProvider = { TlsPinState.Pinned(TlsPin("relay.example", "sha256/x")) },
            fallback = fallback,
        )

        factory.newCall(request)

        assertSame(1, pinned.calls)
        assertSame(0, fallback.calls)
    }

    /** The legitimate TOFU window: pairing itself cannot be pinned, because the pin comes from it. */
    @Test
    fun fallsBackUnpinnedOnlyBeforeTheFirstPairing() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.NeverPaired },
            fallback = fallback,
        )

        factory.newCall(request)

        assertSame(1, fallback.calls)
    }

    @Test
    fun refusesRatherThanDowngradingWhenAPinWasLost() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.Lost },
            fallback = fallback,
        )

        val call = factory.newCall(request)

        assertSame("the unpinned client must not be reached", 0, fallback.calls)
        assertThrows(SSLPeerUnverifiedException::class.java) { call.execute() }
    }

    /** The refusal has to arrive through the same failure path every other network error does, or
     *  callers will not map it to a user-facing message. */
    @Test
    fun aRefusalReachesTheEnqueueCallbackAsAFailure() {
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.Lost },
            fallback = RecordingFactory(),
        )
        var failure: Throwable? = null

        factory.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: Call, e: java.io.IOException) { failure = e }
            override fun onResponse(call: Call, response: Response) = Unit
        })

        assertTrue("expected an IOException, got $failure", failure is SSLPeerUnverifiedException)
    }
}
