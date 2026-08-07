package com.urlxl.mail.pgp

/**
 * JVM fakes for all five enrollment ports, plus a [FakePorts] bundle that wires a ceremony from
 * them. This repo has no mocking framework — see `com.urlxl.mail.testing.FakeCalls` for the same
 * approach one layer down.
 *
 * `internal`, not `private`: Kotlin compiles a top-level `private` class to a package-level JVM
 * name, so a second file in this package declaring the same name fails to compile as a duplicate
 * class. That already cost this package four near-identical copies of one fake.
 */
/** The fingerprint the fake identity reports, and so the one a valid envelope's AAD must bind. */
internal const val FAKE_FINGERPRINT = "164D5B834E7FE927"

internal const val FAKE_PLAINTEXT =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot a real key\n-----END-----"

/**
 * Seals a real envelope the fake ports can open, using the same primitives the browser does.
 *
 * Lives here rather than in one test class because the seam it exercises — the state machine against
 * the pure crypto in `DeviceEnvelope.kt` — is reached from more than one suite, and a second private
 * copy is how this package previously ended up with four near-identical versions of one fake.
 *
 * The shared secret is whatever [FakeEnrollmentKeys.sharedSecretResult] returns: the ECDH is the one
 * step a JVM test cannot perform, and it is covered on hardware by `EnrollmentKeyStoreTest`.
 */
internal fun sealEnvelope(
    keys: FakeEnrollmentKeys,
    deviceId: String = "dev-1",
    aadFingerprint: String = FAKE_FINGERPRINT,
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
    val ct = cipher.doFinal(FAKE_PLAINTEXT.toByteArray(Charsets.UTF_8))
    val b64 = java.util.Base64.getEncoder()
    return """
        {"v":"2","alg":"ECDH-P256+HKDF-SHA256+A256GCM",
         "epk":"${b64.encodeToString(ephemeral)}",
         "iv":"${b64.encodeToString(iv)}",
         "ct":"${b64.encodeToString(ct)}"}
    """.trimIndent().replace("\n", "")
}

internal class FakeIdentitySource(private val result: IdentityCheck) : IdentitySource {
    var checkCalls = 0
        private set

    override suspend fun check(): IdentityCheck {
        checkCalls++
        return result
    }
}

/**
 * [rawPublicKey] and [encodedPublicKey] deliberately **disagree**.
 *
 * The one security property the device half owns is that the code derives from the key in this
 * device's own keystore, never from anything the server sent back or from a cached copy of what was
 * published. A fake whose two accessors returned the same point could not tell a correct
 * implementation from one that derived the code from the value it published — both would be green.
 * Making them differ is what turns that into a test that fails when the derivation moves.
 */
internal class FakeEnrollmentKeys(
    private val keyByte: Byte = 0x11,
    private val publishedByte: Byte = 0x22,
    private val minting: Boolean = true,
) : EnrollmentKeys {
    var newKeyPairCalls = 0
        private set
    var deleteCalls = 0
        private set
    var sharedSecretResult: ByteArray? = ByteArray(32) { 0x33 }
    private var exists = false

    /**
     * Destroys the key from under a running ceremony, as `SecurityWipe` and Hostile Location
     * Protection both genuinely can: both tear the enrollment down on a live screen. Set from a test's
     * `onState` to reach the mid-window branch, which no list of canned results can produce.
     */
    var vanished = false

    /** A key that mints but whose public half cannot be read back — the Keystore entry exists while
     *  `getCertificate` returns nothing. Separate from [vanished] because it is reachable
     *  synchronously, immediately after a *successful* mint. */
    var encodingFails = false

    /** The point the code must be derived from. */
    val keystorePoint: ByteArray = ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = keyByte }

    /** A *different* point, standing in for "whatever was published". Nothing correct derives the
     *  code from this. */
    private val publishedPoint: ByteArray =
        ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = publishedByte }

    override fun newKeyPair(): Boolean {
        newKeyPairCalls++
        exists = minting
        return minting
    }

    override fun rawPublicKey(): ByteArray? = keystorePoint.takeIf { exists && !vanished }

    override fun encodedPublicKey(): String? =
        publishedPoint.takeIf { exists && !vanished && !encodingFails }
            ?.let { java.util.Base64.getEncoder().encodeToString(it) }

    override fun sharedSecret(epk: ByteArray): ByteArray? = sharedSecretResult

    override fun deleteKeyPair(): Boolean {
        deleteCalls++
        exists = false
        return true
    }
}

/**
 * [fetchResults] is consumed one entry per poll; when it runs out, [fetchWhenExhausted] is returned
 * forever. That is how a test says "404 twice, then the envelope" or "404 until the window closes".
 */
internal class FakeEnrollmentTransport(
    private val deviceId: String? = "dev-1",
    var publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    private val fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    /** `var` so a test can change what a *later* window sees. A five-minute window is ~100 fetches,
     *  so "404 for the whole first window, then the envelope" is not expressible as a list. */
    var fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    var reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
) : EnrollmentTransport {
    val publishedKeys = mutableListOf<String>()
    val reported = mutableListOf<Boolean>()
    var fetchCalls = 0
        private set
    var durableReports = 0
        private set

    override suspend fun deviceId(): String? = deviceId

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult {
        publishedKeys += encodedPublicKey
        return publishResult
    }

    override suspend fun fetchEnvelope(): EnrollmentCallResult {
        fetchCalls++
        return if (fetchResults.isEmpty()) fetchWhenExhausted else fetchResults.removeAt(0)
    }

    override suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult {
        reported += enrolled
        return reportResult
    }

    override fun enqueueDurableReport() {
        durableReports++
    }
}

internal class FakeDecryptedMailCache(private val cachedRows: Int = 3) : DecryptedMailCache {
    var clearCalls = 0
        private set

    override suspend fun clearServerDecryptedBodies(): Int {
        clearCalls++
        return cachedRows
    }
}

internal class FakeVaultSealer(
    var outcome: SealOutcome = SealOutcome.Sealed,
) : VaultSealer {
    /** A copy of what was handed over, taken before the ceremony zeroes the caller's array, so a
     *  test can prove the original was wiped without the fake's own copy being wiped too. */
    val received = mutableListOf<ByteArray>()

    /** The caller's array itself, kept by reference so a test can assert it was zeroed in place. */
    val handedArrays = mutableListOf<ByteArray>()

    override suspend fun seal(plaintext: ByteArray): SealOutcome {
        received += plaintext.copyOf()
        handedArrays += plaintext
        return outcome
    }
}

/**
 * A clock the test drives. [sleep] does not sleep — it advances [elapsedRealtimeMs] and
 * [epochSeconds] by exactly the amount asked for, so a five-minute polling window costs a hundred
 * iterations of arithmetic rather than five minutes of wall clock.
 */
internal class FakeEnrollmentClock(
    // 1_680_000_000 / 120 is exactly 14_000_000, so the clock starts on a bucket boundary and a
    // test can count boundary crossings without arithmetic in its head.
    startEpochSeconds: Long = 1_680_000_000L,
    startElapsedMs: Long = 10_000L,
) : EnrollmentClock {
    var epochMs: Long = startEpochSeconds * 1_000
    var elapsedMs: Long = startElapsedMs
    val sleeps = mutableListOf<Long>()

    override fun epochSeconds(): Long = epochMs / 1_000

    override fun elapsedRealtimeMs(): Long = elapsedMs

    override suspend fun sleep(millis: Long) {
        sleeps += millis
        elapsedMs += millis
        epochMs += millis
    }
}

/**
 * Every port, a recorded transcript of the states the ceremony emitted, and a factory.
 *
 * One constructor with named defaults, not an overload set. Two constructors whose parameters both
 * default would be ambiguous at any call site that names only a parameter they share.
 */
internal class FakePorts(
    identityResult: IdentityCheck = IdentityCheck.ClientProtected("164D5B834E7FE927"),
    deviceIdValue: String? = "dev-1",
    private val hostileLocation: Boolean = false,
    private val secureLockScreen: Boolean = true,
    publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    /** A keystore that refuses to mint — StrongBox and the TEE fallback both failing. Exposed here
     *  because [FailureReason.NO_DEVICE_KEY] was otherwise unreachable from any test: this bundle
     *  hardcoded a minting keystore, so the branch had production call sites and no coverage. */
    minting: Boolean = true,
) {
    val identity = FakeIdentitySource(identityResult)
    val keys = FakeEnrollmentKeys(minting = minting)
    val transport = FakeEnrollmentTransport(
        deviceId = deviceIdValue,
        publishResult = publishResult,
        fetchResults = fetchResults,
        fetchWhenExhausted = fetchWhenExhausted,
        reportResult = reportResult,
    )
    val sealer = FakeVaultSealer()
    val mailCache = FakeDecryptedMailCache()
    val clock = FakeEnrollmentClock()

    /** Every state the ceremony emitted, in order. */
    val states = mutableListOf<EnrollmentUiState>()

    fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(
        identity = identity,
        transport = transport,
        keys = keys,
        sealer = sealer,
        mailCache = mailCache,
        clock = clock,
        hostileLocationEnabled = { hostileLocation },
        hasSecureLockScreen = { secureLockScreen },
        onState = { states += it },
    )
}
