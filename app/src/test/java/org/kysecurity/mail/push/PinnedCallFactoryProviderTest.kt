package org.kysecurity.mail.push

import okhttp3.Call
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class PinnedCallFactoryProviderTest {

    private fun pin(host: String) = TlsPin(host, setOf("sha256/${"A".repeat(43)}="))

    /** THE REGRESSION. The pin used to be sampled BEFORE the lock and then trusted inside it, so
     *  a re-pair that landed while a caller waited republished a client for the SUPERSEDED relay.
     *  That client pins one host and passes every other one vacuously, which is how a credentialed
     *  request to the current relay ends up back on plain system trust.
     *
     *  Driven through the pin provider rather than through threads, because the provider is where
     *  the two reads happen: read 1 is the stale sample taken before the lock, read 2 is what the
     *  store actually holds by the time a client would be built. Deterministic, and it fails on the
     *  old code, which returns the superseded pin and leaves it in the cache for everyone else. */
    @Test
    fun aPinThatChangesWhileTheCallerWaitsIsNotBuiltFromTheStaleRead() {
        val superseded = pin("old-relay.example")
        val current = pin("new-relay.example")
        var reads = 0
        val provider = PinnedCallFactoryProvider(
            tlsPinProvider = { if (reads++ == 1) superseded else current },
        )

        val warm = provider.invoke() // read 0: fills the cache with the current pin.
        val afterStaleRead = provider.invoke() // read 1 is stale; read 2 is taken under the lock.

        assertEquals(current, warm?.first)
        assertEquals(current, afterStaleRead?.first)
        assertSame("and the cached client must survive the stale read", warm?.second, afterStaleRead?.second)
    }

    /** The client the caller gets back and the pin it enforces are one value, so the caller can
     *  check the pin against the request instead of hoping the two still agree. */
    @Test
    fun aReplacedPinIsNeverServedFromTheCache() {
        val stored = AtomicReference(pin("relay.example"))
        val provider = PinnedCallFactoryProvider(tlsPinProvider = { stored.get() })

        val first = provider.invoke()
        stored.set(pin("other-relay.example"))
        val second = provider.invoke()

        assertEquals(pin("relay.example"), first?.first)
        assertEquals(pin("other-relay.example"), second?.first)
    }

    @Test
    fun noPinYieldsNoClient() {
        assertEquals(null, PinnedCallFactoryProvider(tlsPinProvider = { null }).invoke())
    }

    /** Why the lock is there at all: concurrent callers share one client rather than each building
     *  their own. Racy by construction, so it asserts only what is true on every interleaving. */
    @Test
    fun concurrentCallersOnAStablePinShareOneClient() {
        val stable = pin("relay.example")
        val provider = PinnedCallFactoryProvider(tlsPinProvider = { stable })
        val start = CountDownLatch(1)
        val done = CountDownLatch(8)
        val clients = java.util.Collections.synchronizedList(mutableListOf<Call.Factory?>())

        repeat(8) {
            Thread {
                start.await()
                clients += provider.invoke()?.second
                done.countDown()
            }.start()
        }
        start.countDown()
        check(done.await(10, TimeUnit.SECONDS)) { "provider threads did not finish" }

        assertEquals(8, clients.size)
        clients.forEach { assertSame(clients.first(), it) }
    }
}
