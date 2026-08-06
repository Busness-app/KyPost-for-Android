package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/**
 * The tail of the ceremony, and the exit table.
 *
 * A real envelope is built here rather than mocked, because the seam being tested is exactly the one
 * between the state machine and the pure crypto in `DeviceEnvelope.kt`: a ceremony that assembled the
 * AAD or the HKDF salt wrongly would still "work" against a stubbed opener.
 */
class EnrollmentCeremonyExitTest {

    private val fingerprint = "164D5B834E7FE927"

    /**
     * Seals a real envelope the fake ports can open, using the same primitives the browser does.
     *
     * The shared secret is whatever [FakeEnrollmentKeys.sharedSecretResult] returns — the ECDH is
     * the one step a JVM test cannot perform, and it is already covered on hardware by
     * `EnrollmentKeyStoreTest`.
     */
    private fun sealEnvelope(
        keys: FakeEnrollmentKeys,
        deviceId: String = "dev-1",
        aadFingerprint: String = fingerprint,
    ): String {
        val sharedSecret = requireNotNull(keys.sharedSecretResult)
        val ephemeral = ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = 0x44 }
        val key = hkdfSha256(
            ikm = sharedSecret,
            salt = keys.keystorePoint,
            info = "kypost-device-envelope/v2".toByteArray(Charsets.UTF_8),
            length = 32,
        )
        val iv = ByteArray(12) { 0x55 }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(key, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, iv),
            )
            updateAAD(deviceEnvelopeAad(deviceId, aadFingerprint))
        }
        val ct = cipher.doFinal(PLAINTEXT.toByteArray(Charsets.UTF_8))
        val b64 = Base64.getEncoder()
        return """
            {"v":"2","alg":"ECDH-P256+HKDF-SHA256+A256GCM",
             "epk":"${b64.encodeToString(ephemeral)}",
             "iv":"${b64.encodeToString(iv)}",
             "ct":"${b64.encodeToString(ct)}"}
        """.trimIndent().replace("\n", "")
    }

    private fun portsWithEnvelope(
        sealFor: String = "dev-1",
        aadFingerprint: String = fingerprint,
    ): FakePorts {
        val probe = FakeEnrollmentKeys()
        val envelope = sealEnvelope(probe, sealFor, aadFingerprint)
        return FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope)))
    }

    @Test
    fun aSealedEnvelopeReachesEnrolled() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(true), ports.transport.reported)
        assertEquals("the agreement key is spent on success too", 1, ports.keys.deleteCalls)
        assertEquals("no durable fallback was needed", 0, ports.transport.durableReports)
    }

    /** The sealer receives what the browser sealed, byte for byte. Anything else means the AAD, the
     *  HKDF salt or the parse is wrong, and the user would see the substituted-key alarm. */
    @Test
    fun theSealerReceivesTheOpenedPlaintext() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertArrayEquals(PLAINTEXT.toByteArray(Charsets.UTF_8), ports.sealer.received.single())
    }

    /**
     * The plaintext is the account's PGP private key. Its lifetime is the real exposure, and it does
     * NOT go into `EnrollmentSession` — that holder has no consumer until the deferred decryption
     * work lands, and populating it for zero readers is exposure bought for nothing.
     */
    @Test
    fun thePlaintextIsZeroedInPlaceAfterSealing() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        val handed = ports.sealer.handedArrays.single()
        assertTrue("every byte must be zero", handed.all { it == 0.toByte() })
    }

    /**
     * **A failed report still means enrolled.** The local seal is real; only the server's marker is
     * stale, and the durable worker already exists to correct it. Reporting this as a failure would
     * make the user re-run a ceremony whose expensive half already succeeded.
     */
    @Test
    fun aFailedReportStillMeansEnrolledAndEnqueuesTheWorker() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            reportResult = EnrollmentCallResult.Failed("offline"),
        )

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, ports.transport.durableReports)
        assertEquals(1, ports.keys.deleteCalls)
    }

    /**
     * **A failed GCM open is never a retry.** The AAD binds device and identity, so a failure means
     * the envelope was sealed for another device or under an identity the account no longer
     * advertises. Here the envelope was sealed for a different device id.
     */
    @Test
    fun anEnvelopeSealedForAnotherDeviceIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(sealFor = "some-other-device")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("no second attempt", 1, ports.transport.fetchCalls)
    }

    /** The other half of the AAD binding: an envelope minted under a fingerprint this account no
     *  longer advertises. Same verdict, same copy — the phone cannot tell the two apart, and the
     *  copy must not claim it can. */
    @Test
    fun anEnvelopeSealedUnderAnotherIdentityIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(aadFingerprint = "AAAABBBBCCCCDDDD")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
    }

    /** The ECDH itself can fail — a malformed peer point that got past the parse, or a key the
     *  Keystore will no longer agree with. Indistinguishable from a hostile envelope from here, and
     *  treated the same: no retry. */
    @Test
    fun anEcdhFailureIsCouldNotOpenAndDestroysTheKeypairWithNoSecondAttempt() = runBlocking {
        val ports = portsWithEnvelope()
        ports.keys.sharedSecretResult = null

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("no second attempt", 1, ports.transport.fetchCalls)
    }

    @Test
    fun aMalformedEnvelopeIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope("""{"v":"1"}""")),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.ENVELOPE_MALFORMED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    /** The lock screen can be removed between the gate and the seal. `EnrollmentVault.ensureKey()`
     *  reports it, and the ceremony must not present it as a mysterious failure. */
    @Test
    fun losingTheLockScreenBeforeTheSealIsItsOwnReason() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.NoSecureLockScreen

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.NO_SECURE_LOCK_SCREEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aSealFailureIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Failed("keystore said no")

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.SEAL_FAILED), ports.states.last())
        assertEquals(1, ports.keys.deleteCalls)
    }

    /**
     * A cancel is not a failure. The envelope is still on the relay, so the user gets the code back
     * and a way to try again — and the plaintext does not survive the round trip.
     *
     * The window ends rather than re-prompting three seconds later; see deviation 8 in this plan.
     *
     * Also binds [EnrollmentCeremony.isIdle] to the window rather than to the state alone: `run()`'s
     * `finally` sets it back to `true` on every path including a throw, so asserting it only after
     * `run()` returns is true by construction and cannot fail. Reading it from *inside* `onState` —
     * the moment the window's `ShowingCode` is emitted, before the cancel — is what actually exercises
     * the `isIdle = false` at the top of `run()`.
     */
    @Test
    fun aCancelledBiometricReturnsToTheCodeWithThePlaintextZeroed() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Cancelled

        lateinit var ceremony: EnrollmentCeremony
        var idleDuringTheWindow: Boolean? = null
        ceremony = EnrollmentCeremony(
            identity = ports.identity,
            transport = ports.transport,
            keys = ports.keys,
            sealer = ports.sealer,
            clock = ports.clock,
            hostileLocationEnabled = { false },
            hasSecureLockScreen = { true },
            onState = { state ->
                ports.states += state
                if (state is EnrollmentUiState.ShowingCode && idleDuringTheWindow == null) {
                    idleDuringTheWindow = ceremony.isIdle
                }
            },
        )

        ceremony.run()

        assertTrue(
            "a dismissed prompt must not send the user back to the code: this path is only reachable " +
                "because the browser already read it and sealed, and the value would go stale on the " +
                "next bucket with no window left to refresh it",
            ports.states.last() is EnrollmentUiState.ReadyToFinish,
        )
        assertTrue(ports.sealer.handedArrays.single().all { it == 0.toByte() })
        assertEquals("a cancel destroys nothing", 0, ports.keys.deleteCalls)
        assertEquals("the window must run with isIdle false", false, idleDuringTheWindow)
        assertTrue("the user must be able to try again", ceremony.isIdle)
    }

    /** Leaving the screen is the restart path, and it must take the key with it. */
    @Test
    fun teardownDestroysALiveKeypairAndIsIdempotent() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()
        ceremony.teardown()

        assertEquals(1, ports.keys.deleteCalls)
    }

    /** A ceremony blocked at the gate never minted anything, so teardown must not claim a deletion
     *  it did not perform — `EnrollmentTeardown` feeds that boolean to a `SecurityWipe.step`. */
    @Test
    fun teardownAfterABlockedGateDestroysNothing() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()

        assertEquals(0, ports.keys.deleteCalls)
    }

    /**
     * **The exit table, made structural.**
     *
     * The `when` below is exhaustive over [EnrollmentUiState] with no `else`, so adding a state
     * without deciding its cleanup is a **compile error**, not a silently untested path. That is the
     * point: an exit added later without cleanup is exactly the defect this ceremony cannot afford.
     */
    private enum class Cleanup {
        DESTROYS_THE_KEYPAIR,
        KEEPS_THE_KEYPAIR,
        NOTHING_WAS_MINTED,

        /** Reaching one of these as a ceremony's last state is itself the bug. */
        NOT_A_TERMINAL_STATE,
    }

    private fun expectedCleanup(state: EnrollmentUiState): Cleanup = when (state) {
        // Transient. A ceremony that stops here has stalled somewhere it must not.
        EnrollmentUiState.CheckingIdentity,
        EnrollmentUiState.PublishingKey,
        EnrollmentUiState.Opening,
        EnrollmentUiState.AwaitingAuth,
        -> Cleanup.NOT_A_TERMINAL_STATE

        // Blocked at the gate: no keypair was ever minted.
        is EnrollmentUiState.Unavailable -> Cleanup.NOTHING_WAS_MINTED

        // The one exit that keeps it — "Check again" resumes against the same key.
        is EnrollmentUiState.WaitingTimedOut -> Cleanup.KEEPS_THE_KEYPAIR

        // A ShowingCode left as the LAST state means a window closed without reaching any exit —
        // the cancelled seal now lands on ReadyToFinish instead, so nothing legitimately stops here.
        is EnrollmentUiState.ShowingCode -> Cleanup.NOT_A_TERMINAL_STATE

        // The cancelled seal. The envelope is already on the relay and the key is what opens it, so
        // "Check again" must find both still in place.
        EnrollmentUiState.ReadyToFinish -> Cleanup.KEEPS_THE_KEYPAIR

        // Success spends the key exactly as failure does. A key that outlives every ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        EnrollmentUiState.Enrolled -> Cleanup.DESTROYS_THE_KEYPAIR
        is EnrollmentUiState.Failed -> Cleanup.DESTROYS_THE_KEYPAIR
    }

    @Test
    fun everyTerminalExitMatchesItsRowInTheExitTable() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val cases: List<Pair<String, FakePorts>> = listOf(
            "hostile location" to FakePorts(hostileLocation = true),
            "no lock screen" to FakePorts(secureLockScreen = false),
            "not paired" to FakePorts(deviceIdValue = null),
            "no identity" to FakePorts(identityResult = IdentityCheck.NoIdentity),
            "server-held" to FakePorts(identityResult = IdentityCheck.ServerHeld),
            "could not check" to FakePorts(identityResult = IdentityCheck.CouldNotCheck),
            "publish rejected" to FakePorts(publishResult = EnrollmentCallResult.Failed("no")),
            "publish 401" to FakePorts(publishResult = EnrollmentCallResult.Unauthorized),
            "publish 429" to FakePorts(publishResult = EnrollmentCallResult.RateLimited(1L)),
            "poll timeout" to FakePorts(),
            "poll 401" to FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized)),
            "malformed envelope" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope("nonsense")),
            ),
            "could not open" to FakePorts(
                fetchResults = mutableListOf(
                    EnrollmentCallResult.Envelope(sealEnvelope(probe, deviceId = "elsewhere")),
                ),
            ),
            "success" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            ),
            "report failed" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
                reportResult = EnrollmentCallResult.Unauthorized,
            ),
        )

        for ((name, ports) in cases) {
            ports.ceremony().run()
            val terminal = ports.states.last()
            val deletions = ports.keys.deleteCalls
            when (expectedCleanup(terminal)) {
                Cleanup.DESTROYS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must destroy the keypair", 1, deletions)
                Cleanup.KEEPS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must keep the keypair", 0, deletions)
                Cleanup.NOTHING_WAS_MINTED ->
                    assertEquals("$name: blocked at the gate, so there is nothing to destroy", 0, deletions)
                Cleanup.NOT_A_TERMINAL_STATE ->
                    fail("$name: the ceremony stopped in a transient state: $terminal")
            }
        }
    }

    private companion object {
        const val PLAINTEXT = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot a real key\n-----END-----"
    }
}
