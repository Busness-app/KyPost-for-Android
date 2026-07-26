package com.urlxl.mail

import com.urlxl.mail.pgp.PgpBootstrapClient
import com.urlxl.mail.pgp.PgpComposeState
import com.urlxl.mail.pgp.RecipientKeyClient
import com.urlxl.mail.push.PairingData
import com.urlxl.mail.testing.FakeCallFactory
import com.urlxl.mail.testing.response
import kotlinx.coroutines.runBlocking
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.Before
import org.junit.Test

private fun testPairing(deviceId: String = "d", deviceSecret: String = "s") = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = deviceId,
    deviceSecret = deviceSecret,
    pairedAtEpochMs = 0L,
)

class ComposePgpControllerTest {

    /** The bootstrap cache is process-scoped, so it has to be cleared between tests. */
    @Before
    fun clearCache() = ComposePgpController.resetSessionCache()

    // ---- splitAddresses ----

    @Test
    fun splitAddresses_flattensTheThreeCommaJoinedFields() {
        assertEquals(
            listOf("a@example.com", "b@example.com", "c@example.com"),
            splitAddresses("a@example.com, b@example.com", "", "c@example.com"),
        )
    }

    /** The same address in To and CC is one recipient to check, and duplicate names in the
     *  confirmation dialog would read as two different people. */
    @Test
    fun splitAddresses_deduplicatesCaseInsensitively() {
        assertEquals(
            listOf("a@example.com"),
            splitAddresses("a@example.com", "A@Example.com", ""),
        )
    }

    @Test
    fun splitAddresses_dropsBlanksAndTrimsWhitespace() {
        assertEquals(listOf("a@example.com"), splitAddresses(" a@example.com , , ", "", ""))
    }

    // ---- composeState ----

    @Test
    fun composeState_mapsBootstrapThroughPgpComposeStateOf() = runBlocking {
        val controller = controllerWith(bootstrapBody = """{"hasIdentity":true,"protection":"server"}""")

        assertEquals(
            PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    /** Not paired is not "no identity": there is no account to ask about, so nothing is offered. */
    @Test
    fun composeState_withoutPairing_hidesEverything() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    /** The cache is `companion object`-scoped (process-wide), not per-instance — a controller
     *  created fresh for a second compose screen still must not re-hit the network. Calling
     *  composeState() twice on the *same* instance would pass even against a per-instance cache,
     *  so this exercises two separate instances sharing one call factory to actually pin the
     *  process-wide scoping the design (and [PushRepository.purgeAccountScopedData]'s explicit
     *  invalidation of it on unpair) depends on. */
    @Test
    fun composeState_cachesASuccessForTheProcess() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, """{"hasIdentity":true,"protection":"server"}""", 200)
        }
        val firstController = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )
        val secondController = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        firstController.composeState()
        secondController.composeState()

        assertEquals(1, calls)
    }

    /** A failure must not be cached: one flaky request would otherwise disable encryption for the
     *  rest of the session. */
    @Test
    fun composeState_doesNotCacheAFailure() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, "unavailable", 503)
        }
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        controller.composeState()
        controller.composeState()

        assertEquals(2, calls)
    }

    // ---- keylessRecipients ----

    @Test
    fun keylessRecipients_returnsTheAddressesWithNoKeyOnFile() = runBlocking {
        val body = """{"results":[
            {"address":"a@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"b@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val controller = controllerWith(recipientBody = body)

        assertEquals(
            listOf("b@example.com"),
            controller.keylessRecipients(listOf("a@example.com", "b@example.com")),
        )
    }

    /** A failed preflight yields no warning rather than a false one. The 409 is the real gate, so
     *  a failed lookup can never be the reason the fallback gets used. */
    @Test
    fun keylessRecipients_isEmptyOnFailure() = runBlocking {
        val controller = controllerWith(recipientStatus = 500, recipientBody = "boom")

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    @Test
    fun keylessRecipients_withoutPairing_isEmpty() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    private fun controllerWith(
        bootstrapBody: String = """{"hasIdentity":true,"protection":"server"}""",
        recipientBody: String = """{"results":[]}""",
        recipientStatus: Int = 200,
    ) = ComposePgpController(
        pairingProvider = { testPairing() },
        bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, bootstrapBody, 200) }),
        recipientKeyClient = RecipientKeyClient(
            callFactory = FakeCallFactory { request -> response(request, recipientBody, recipientStatus) },
        ),
    )
}
