package org.kysecurity.mail

import android.content.Context
import org.kysecurity.mail.pgp.EnrollmentVault
import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.PgpBootstrapResult
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.pgp.RecipientKeyResult
import org.kysecurity.mail.pgp.isEnrolled
import org.kysecurity.mail.pgp.pgpComposeStateOf
import org.kysecurity.mail.pgp.probeEnrollment
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Flattens the compose screen's three comma-joined recipient fields into one address list for the
 * preflight.
 *
 * Deduplicates case-insensitively: the same address in To and CC is one recipient to check, and
 * naming it twice in the confirmation dialog would read as two different people. The first spelling
 * wins, since that is the one the user typed and expects to see.
 */
fun splitAddresses(vararg commaJoined: String): List<String> {
    val seen = mutableSetOf<String>()
    return commaJoined
        .flatMap { it.split(',') }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filter { seen.add(it.lowercase()) }
}

/**
 * The compose screen's PGP decisions, kept out of [ComposeActivity] so they are testable without a
 * Context and so the Activity stays a view.
 *
 * Nothing here decides whether to *send*. The confirmation is driven by the relay's 409, not by the
 * preflight — see [keylessRecipients].
 */
class ComposePgpController(
    private val pairingProvider: () -> PairingData?,
    private val bootstrapClient: PgpBootstrapClient,
    private val recipientKeyClient: RecipientKeyClient,
    /** Whether this device still holds the account's private key. Injected so the controller stays
     *  Context-free and JVM-testable; the real one probes the Keystore via `probeEnrollment`. */
    private val enrollmentProbe: suspend () -> Boolean = { false },
) {

    /**
     * Which PGP controls this account gets.
     *
     * The **bootstrap** is cached for the process on success only — caching a failure would disable
     * encryption for the rest of the session over one flaky request. Enrollment deliberately is
     * **not** cached: custody mode is fixed at key creation, but the user can enrol part-way through
     * a session and the OS can invalidate the Keystore key underneath us, so it is re-probed on
     * every call.
     *
     * Returns the everything-hidden state when the device is not paired or bootstrap fails:
     * couldn't-check is not "no".
     */
    suspend fun composeState(): PgpComposeState {
        val bootstrap = bootstrap() ?: return pgpComposeStateOf(hasIdentity = null, protection = null)
        return pgpComposeStateOf(
            hasIdentity = bootstrap.hasIdentity,
            protection = bootstrap.protection,
            deviceEnrolled = enrollmentProbe(),
            accountAddress = bootstrap.accountAddress,
        )
    }

    /** The address every client-encrypted delivery's `From` must carry. Blank when unknown, which
     *  [pgpComposeStateOf] already degrades to the webmail handoff. */
    suspend fun accountAddress(): String = bootstrap()?.accountAddress.orEmpty()

    /** The cached bootstrap, or null when unpaired or the fetch failed. */
    private suspend fun bootstrap(): PgpBootstrapResult.Success? {
        cachedBootstrap?.let { return it }
        // pairingProvider() reaches SecurePairingStore.pairingSnapshot(), which reads
        // Keystore-backed EncryptedSharedPreferences and does an AES unwrap — disk plus crypto —
        // so it must not run on the caller's dispatcher, which is Main for every call site today.
        val pairing = withContext(Dispatchers.IO) { pairingProvider() }
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return null
        return when (val result = bootstrapClient.fetch(pairing.serverUrl, deviceId, deviceSecret)) {
            is PgpBootstrapResult.Success -> result.also { cachedBootstrap = it }
            is PgpBootstrapResult.Failed -> null
        }
    }

    /**
     * The addresses with no usable key **in the user's contacts**, for an inline warning.
     *
     * A lower bound, never a promise: the send path also runs WKD and keyserver discovery, so an
     * address here may still be encrypted to successfully. A failure yields an empty list — no
     * warning rather than a false one — which is safe because the relay's 409 is the actual gate,
     * so a failed preflight can never be the reason the pickup fallback gets used.
     */
    suspend fun keylessRecipients(addresses: List<String>): List<String> {
        // Same off-main-thread rationale as composeState() above.
        val pairing = withContext(Dispatchers.IO) { pairingProvider() }
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return emptyList()
        return when (val result = recipientKeyClient.check(pairing.serverUrl, deviceId, deviceSecret, addresses)) {
            is RecipientKeyResult.Success -> result.keyless
            is RecipientKeyResult.Failed -> emptyList()
        }
    }

    companion object : ProcessScopedState {
        /** Process-scoped, so a second compose in the same session costs no round trip. Not
         *  persisted: custody mode is fixed at key creation. An account switch does **not**
         *  restart the process — [org.kysecurity.mail.push.PushRepository.unpairDevice] only clears
         *  pairing and cancels the pull worker — so this cache has to be dropped at a session
         *  boundary via [ProcessScopedState]. Without that, a switch from a client-custody account
         *  to a server-custody one would keep hiding the Encrypt/Sign chips for the rest of the
         *  process.
         *
         *  Holds the **bootstrap**, not the composed state: enrollment is an input to that state
         *  and can change within one process, so it is re-probed rather than frozen here. */
        @Volatile
        private var cachedBootstrap: PgpBootstrapResult.Success? = null

        init {
            ProcessState.register(this)
        }

        override fun resetForNewSession() = resetSessionCache()

        fun resetSessionCache() {
            cachedBootstrap = null
        }

        /** Wires the real, TLS-pinned clients. Mirrors [org.kysecurity.mail.pgp.hasPgpIdentity]'s
         *  Context-based default. */
        fun from(context: Context): ComposePgpController = ComposePgpController(
            pairingProvider = { PushRuntime.graph(context).repository.pairingForAuthenticatedCall() },
            bootstrapClient = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(context)),
            recipientKeyClient = RecipientKeyClient(callFactory = pinnedPairingCallFactory(context)),
            // Probes the Keystore rather than any bookkeeping of ours, so it stays honest across an
            // app reinstall or an OS key invalidation. Both the EncryptedSharedPreferences read and
            // the Keystore lookup touch disk, hence Dispatchers.IO.
            enrollmentProbe = {
                withContext(Dispatchers.IO) { probeEnrollment(EnrollmentVault(context)).isEnrolled() }
            },
        )
    }
}
