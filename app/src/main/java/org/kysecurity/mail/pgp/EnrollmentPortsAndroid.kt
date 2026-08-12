package org.kysecurity.mail.pgp

import android.content.Context
import android.os.SystemClock
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

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

    // withContext(IO) covers the whole body, not just the fetch: pairingForAuthenticatedCall() is
    // roughly eight EncryptedSharedPreferences decrypts plus a CredentialCipher.unwrap, and on the
    // first call it also forces the lazy EncryptedSharedPreferences/Tink construction and a MasterKey
    // Keystore round trip. The ceremony runs on viewModelScope's Dispatchers.Main.immediate, so
    // without this that lands on the UI thread. PgpBootstrapClient.fetch nests its own
    // withContext(IO), which costs nothing when we are already there. See SecuritySettingsActivity,
    // where the same call was wrapped for the same reason.
    override suspend fun check(): IdentityCheck = withContext(Dispatchers.IO) {
        val pairing = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Not "no identity". The credential may simply be gated and the app currently locked.
            return@withContext IdentityCheck.CouldNotCheck
        }

        // The pinned factory, not PgpBootstrapClient's unpinned default. This request carries the
        // device bearer credential, like every other credentialed call in this app.
        val client = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(appContext))
        identityCheckFrom(client.fetch(pairing.serverUrl, deviceId, deviceSecret))
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

    /**
     * Blocking, and never to be called from the main thread: one call is roughly eight
     * `EncryptedSharedPreferences` decrypts plus a `CredentialCipher.unwrap`, and the first one also
     * forces the lazy `EncryptedSharedPreferences`/Tink construction and a MasterKey Keystore round
     * trip. Every method below therefore opens with `withContext(Dispatchers.IO)` — the port is the
     * Android edge, and it is where this belongs.
     *
     * Wrapping only the client call underneath would not have been enough: the client switches to IO
     * *after* this has already run, so on the ceremony's `Dispatchers.Main.immediate` this landed on
     * the UI thread — from [fetchEnvelope] roughly a hundred times per five-minute window, on a
     * screen that also holds `FLAG_KEEP_SCREEN_ON` and runs a 1 Hz countdown. The clients' own
     * nested `withContext(IO)` costs nothing once we are already on IO.
     */
    private fun pairing() = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        ?.takeIf { !it.deviceId.isNullOrBlank() && !it.deviceSecret.isNullOrBlank() }

    override suspend fun deviceId(): String? = withContext(Dispatchers.IO) { pairing()?.deviceId }

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult =
        withContext(Dispatchers.IO) {
            val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
            clients.publishKey(p.serverUrl, p.deviceId!!, p.deviceSecret!!, encodedPublicKey)
        }

    override suspend fun fetchEnvelope(): EnrollmentCallResult = withContext(Dispatchers.IO) {
        val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
        clients.fetchEnvelope(p.serverUrl, p.deviceId!!, p.deviceSecret!!)
    }

    override suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult =
        withContext(Dispatchers.IO) {
            val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
            clients.reportState(p.serverUrl, p.deviceId!!, p.deviceSecret!!, enrolled)
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

/**
 * [DecryptedMailCache] over Room.
 *
 * `withContext(Dispatchers.IO)` for the same reason every method in [AndroidEnrollmentTransport]
 * opens with it: the ceremony runs on `viewModelScope`'s `Dispatchers.Main.immediate`, so an
 * unwrapped DAO write would land a disk write on the main thread. `DataRuntime.graph` is resolved
 * inside the same block rather than in the constructor — building the graph opens the database, and
 * during a wipe that would rebuild the very database being destroyed. See `PushRepository`, which
 * documents the same hazard.
 */
internal class RoomDecryptedMailCache(private val appContext: Context) : DecryptedMailCache {
    override suspend fun clearServerDecryptedBodies(): Int = withContext(Dispatchers.IO) {
        DataRuntime.graph(appContext).database.emailDao().clearServerDecryptedBodies()
    }
}
