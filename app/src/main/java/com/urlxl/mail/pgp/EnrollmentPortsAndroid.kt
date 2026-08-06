package com.urlxl.mail.pgp

import android.content.Context
import android.os.SystemClock
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.delay

/** [EnrollmentKeyStore] behind the port, so the ceremony's cleanup rule is testable on the JVM. */
internal object AndroidEnrollmentKeys : EnrollmentKeys {
    override fun newKeyPair(): Boolean = EnrollmentKeyStore.newKeyPair()
    override fun rawPublicKey(): ByteArray? = EnrollmentKeyStore.rawPublicKey()
    override fun encodedPublicKey(): String? = EnrollmentKeyStore.encodedPublicKey()
    override fun sharedSecret(epk: ByteArray): ByteArray? = EnrollmentKeyStore.sharedSecret(epk)
    override fun deleteKeyPair(): Boolean = EnrollmentKeyStore.deleteKeyPair()
}

/**
 * The identity check, from **one** `GET /api/pgp/bootstrap`.
 *
 * Bootstrap answers all three questions this port is defined by — is there an identity, is it
 * client-protected, and what is its fingerprint — so `hasPgpIdentity` is not called as well. A second
 * request could only ever agree or disagree with the first, and a disagreement has no resolution.
 *
 * The fingerprint is **hashed from the key bytes** by [ownFingerprintFromBootstrap], never read off
 * the response's own `fingerprint` field: that field is a claim sitting beside `publicKey` with no
 * cryptographic tie to it, and this value is about to be bound into an envelope's AAD.
 */
internal class AndroidIdentitySource(context: Context) : IdentitySource {
    private val appContext = context.applicationContext

    override suspend fun check(): IdentityCheck {
        val pairing = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Not "no identity". The credential may simply be gated and the app currently locked.
            return IdentityCheck.CouldNotCheck
        }

        // The pinned factory, not PgpBootstrapClient's unpinned default. This request carries the
        // device bearer credential, like every other credentialed call in this app.
        val client = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(appContext))
        return identityCheckFrom(client.fetch(pairing.serverUrl, deviceId, deviceSecret))
    }
}

/**
 * The pure "degrade, never guess" mapping from one bootstrap response to an [IdentityCheck].
 *
 * Pulled out of [AndroidIdentitySource.check] so the rule is testable on the JVM, without a network
 * fetch or a device — [pgpComposeStateOf] is a standalone pure function for exactly this reason, and
 * its own KDoc says why: "the rule is testable without instrumentation." A future edit that collapses
 * the `else` branch, or lets an unrecognised `protection` fall through to [IdentityCheck.ClientProtected],
 * must fail a test here rather than only being reachable through a real network round trip.
 */
internal fun identityCheckFrom(result: PgpBootstrapResult): IdentityCheck = when (result) {
    is PgpBootstrapResult.Failed -> IdentityCheck.CouldNotCheck
    is PgpBootstrapResult.Success -> when {
        !result.hasIdentity -> IdentityCheck.NoIdentity
        result.protection == PROTECTION_CLIENT ->
            ownFingerprintFromBootstrap(result)
                ?.let { IdentityCheck.ClientProtected(it) }
            // An identity whose key will not parse is not an identity this device can bind
            // an AAD to. Reporting it as "could not check" rather than "no identity" keeps
            // the user's own key from being described as absent.
                ?: IdentityCheck.CouldNotCheck
        result.protection == PROTECTION_SERVER -> IdentityCheck.ServerHeld
        // Degrade, never guess — the same rule pgpComposeStateOf follows. Guessing "client"
        // here starts a ceremony that can only end at a failed GCM open, which is this
        // feature's one alarm.
        else -> IdentityCheck.CouldNotCheck
    }
}

/**
 * The three enrollment calls, with the pairing resolved per call rather than captured.
 *
 * Read at call time and never cached: the credential gate can drop the cached key when the app locks
 * mid-ceremony, and a captured secret would keep working from a state the user has left.
 */
internal class AndroidEnrollmentTransport(context: Context) : EnrollmentTransport {
    private val appContext = context.applicationContext

    // callFactory has no default on EnrollmentClients precisely so this cannot be forgotten; see
    // d410827. The bare default was unpinned, on the one request carrying the device credential.
    private val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(appContext))

    private fun pairing() = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        ?.takeIf { !it.deviceId.isNullOrBlank() && !it.deviceSecret.isNullOrBlank() }

    override suspend fun deviceId(): String? = pairing()?.deviceId

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.publishKey(p.serverUrl, p.deviceId!!, p.deviceSecret!!, encodedPublicKey)
    }

    override suspend fun fetchEnvelope(): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.fetchEnvelope(p.serverUrl, p.deviceId!!, p.deviceSecret!!)
    }

    override suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult {
        val p = pairing() ?: return EnrollmentCallResult.Unauthorized
        return clients.reportState(p.serverUrl, p.deviceId!!, p.deviceSecret!!, enrolled)
    }

    override fun enqueueDurableReport() = EnrollmentStateWorker.enqueue(appContext)
}

/**
 * Whether this device has a PIN, pattern or password.
 *
 * `KeyguardManager.isDeviceSecure` and **not** `EnrollmentVault.ensureKey()`, even though the vault
 * is the authority. `ensureKey()` mutates: on a key that no longer matches the spec it regenerates,
 * and generation clears the stored blob in the same breath. Using it as a read-only probe would mean
 * opening the ceremony screen could destroy an existing enrollment. The vault still has the final
 * word at the seal, where a mutation is expected.
 */
internal fun hasSecureLockScreen(context: Context): Boolean =
    context.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceSecure == true

/**
 * Wall clock for the bucket, monotonic for the deadline.
 *
 * `elapsedRealtime` for the deadline follows `AppLockManager` and `AppLockStore`, whose own comments
 * explain the choice: a wall-clock deadline can be stepped over or never reached when the user or
 * the network changes the date.
 */
internal object SystemEnrollmentClock : EnrollmentClock {
    override fun epochSeconds(): Long = System.currentTimeMillis() / 1_000
    override fun elapsedRealtimeMs(): Long = SystemClock.elapsedRealtime()
    override suspend fun sleep(millis: Long) = delay(millis)
}
