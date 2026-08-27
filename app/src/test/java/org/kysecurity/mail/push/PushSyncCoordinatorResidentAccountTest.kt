package org.kysecurity.mail.push

import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a reconnect leaves behind, and what the next pairing owes it.
 *
 * `resetPairingCredential` drops the pairing proof and KEEPS the mailbox — that is the whole point
 * of the certificate-renewal recovery. So after one, "no pairing" no longer means "no account", and
 * [PushSyncCoordinator.attemptPairing] must decide replacement from the resident-account marker
 * instead. Without it a stranger's QR paired straight over the previous account's mail, contacts,
 * keys and pending-contact outbox with no purge and no warning.
 */
class PushSyncCoordinatorResidentAccountTest {

    private val existing = PairingData(
        subscriberId = "sub-old",
        serverUrl = "https://old.example.com",
        registrationUrl = "https://old.example.com/api/notifications/native/register",
        pairingToken = "tok-old",
        deviceId = "dev-old",
        deviceSecret = "secret-old",
        pairedAtEpochMs = 0L,
    )

    /** The same account coming back after a reconnect: a new token, nothing else changed. */
    private val sameAccountAgain = existing.copy(pairingToken = "tok-fresh", deviceId = null, deviceSecret = null)

    private fun coordinator(
        store: FakePushStore,
        onWipe: suspend (List<String>) -> Unit = {},
    ) = PushSyncCoordinator(
        repository = store,
        registrationClient = NativeRegistrationClient(
            callFactory = FakeCallFactory { req: Request ->
                response(req, """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"secret-new"}""", 200)
            },
        ),
        wipeOnIncompletePurge = onWipe,
        fetchRegistrationCredential = { PushRegistrationCredential(token = "fcm-token") },
    )

    /** A store that has been through "Reconnect to server": paired once, credential reset. */
    private fun reconnectedStore(purgeResidue: List<String> = emptyList()) =
        FakePushStore(pairing = existing, purgeResidue = purgeResidue).apply { resetPairingCredential() }

    @Test
    fun reconnectingAndRePairingTheSameAccountKeepsTheMailbox() = runBlocking {
        val store = reconnectedStore()

        val result = coordinator(store).attemptPairing(sameAccountAgain)

        assertTrue(result is NativeRegistrationResult.Success)
        assertTrue("a reconnect must not cost the user their mail", "clearPairing" !in store.events)
        assertEquals("secret-new", store.currentPairing()?.deviceSecret)
    }

    @Test
    fun reconnectingThenPairingADifferentSubscriberPurges() = runBlocking {
        val store = reconnectedStore()

        val result = coordinator(store).attemptPairing(sameAccountAgain.copy(subscriberId = "sub-new"))

        assertTrue(result is NativeRegistrationResult.Success)
        // Order is the assertion: the purge lands only after the replacement registered.
        assertEquals(listOf("clearPairing", "persist:secret-new"), store.events)
    }

    @Test
    fun reconnectingThenPairingADifferentServerPurges() = runBlocking {
        val store = reconnectedStore()
        val elsewhere = sameAccountAgain.copy(
            serverUrl = "https://new.example.com",
            registrationUrl = "https://new.example.com/api/notifications/native/register",
        )

        coordinator(store).attemptPairing(elsewhere)

        assertEquals(listOf("clearPairing", "persist:secret-new"), store.events)
    }

    /** The escalation the replacement branch owes: survivors carry no subscriber column, so an
     *  incomplete purge must refuse the new account rather than mix the two. */
    @Test
    fun reconnectingThenAnIncompletePurgeRefusesTheNewAccountAndWipes() = runBlocking {
        val store = reconnectedStore(purgeResidue = listOf("database"))
        var wipedWith: List<String>? = null

        val result = coordinator(store, onWipe = { wipedWith = it })
            .attemptPairing(sameAccountAgain.copy(subscriberId = "sub-new"))

        assertTrue(result is NativeRegistrationResult.Error)
        assertEquals(listOf("database"), wipedWith)
        assertEquals(listOf("clearPairing"), store.events)
    }

    /** A device that never paired has nothing resident, so nothing to purge. */
    @Test
    fun aFirstEverPairingPurgesNothing() = runBlocking {
        val store = FakePushStore()

        coordinator(store).attemptPairing(existing)

        assertEquals(listOf("persist:secret-new"), store.events)
    }
}
