package org.kysecurity.mail.contacts

import org.kysecurity.mail.push.PairingData
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers [contactDedupeOutcomeOf] and [resolveDedupeOutcome] — the pure, dependency-free pieces
 * pulled out of [ContactSyncRepository.dedupe] so they're unit-testable without a real
 * Context-backed `AppDatabase`/`ContactCursorStore` (mirrors
 * [org.kysecurity.mail.mail.reconcileFetchResult]'s extraction from `MailRepository` for the same
 * reason — see `MailRepositoryTest.kt`). `ContactSyncRepository` itself still has no direct unit
 * tests; that gap is pre-existing repo-wide infra (no Robolectric/mocking library) and unaffected
 * by this extraction.
 */
class ContactSyncRepositoryTest {

    private val pairing = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/register",
        pairingToken = "token-1",
        deviceId = "device-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private val report = ContactDedupeReportDto(
        mergedCount = 2,
        groups = listOf(ContactDedupeGroupDto(survivor = "uid-1", absorbed = listOf("uid-2"))),
    )

    // --- contactDedupeOutcomeOf: pure ContactDedupeResult -> ContactDedupeOutcome mapping ---

    @Test
    fun contactDedupeOutcomeOf_success_mapsToSuccessWithReport() {
        val outcome = contactDedupeOutcomeOf(ContactDedupeResult.Success(report))

        assertTrue(outcome is ContactDedupeOutcome.Success)
        assertEquals(report, (outcome as ContactDedupeOutcome.Success).report)
    }

    @Test
    fun contactDedupeOutcomeOf_badRequest_foldsIntoRetry() {
        val outcome = contactDedupeOutcomeOf(ContactDedupeResult.BadRequest("bad params"))

        assertTrue(outcome is ContactDedupeOutcome.Retry)
        assertEquals("bad params", (outcome as ContactDedupeOutcome.Retry).message)
    }

    @Test
    fun contactDedupeOutcomeOf_unauthorized_mapsToUnauthorized() {
        val outcome = contactDedupeOutcomeOf(ContactDedupeResult.Unauthorized("bad hash"))

        assertTrue(outcome is ContactDedupeOutcome.Unauthorized)
    }

    @Test
    fun contactDedupeOutcomeOf_serviceUnavailable_mapsToServiceUnavailableWithMessage() {
        val outcome = contactDedupeOutcomeOf(ContactDedupeResult.ServiceUnavailable("not configured"))

        assertTrue(outcome is ContactDedupeOutcome.ServiceUnavailable)
        assertEquals("not configured", (outcome as ContactDedupeOutcome.ServiceUnavailable).message)
    }

    @Test
    fun contactDedupeOutcomeOf_retryable_mapsToRetryWithMessage() {
        val outcome = contactDedupeOutcomeOf(ContactDedupeResult.Retryable("network error"))

        assertTrue(outcome is ContactDedupeOutcome.Retry)
        assertEquals("network error", (outcome as ContactDedupeOutcome.Retry).message)
    }

    // --- resolveDedupeOutcome: the pairing short-circuit that dedupe() decides before calling the client ---

    @Test
    fun resolveDedupeOutcome_noPairing_returnsNotPairedWithoutCallingClient() = runBlocking {
        var dedupeCalled = false

        val outcome = resolveDedupeOutcome(
            pairingProvider = { null },
            dedupeCall = { dedupeCalled = true; ContactDedupeResult.Success(report) },
        )

        assertTrue(outcome is ContactDedupeOutcome.NotPaired)
        assertFalse(dedupeCalled)
    }

    @Test
    fun resolveDedupeOutcome_paired_delegatesToClientAndMapsResult() = runBlocking {
        var receivedPairing: PairingData? = null

        val outcome = resolveDedupeOutcome(
            pairingProvider = { pairing },
            dedupeCall = { p -> receivedPairing = p; ContactDedupeResult.Success(report) },
        )

        assertEquals(pairing, receivedPairing)
        assertTrue(outcome is ContactDedupeOutcome.Success)
        assertEquals(report, (outcome as ContactDedupeOutcome.Success).report)
    }
}
