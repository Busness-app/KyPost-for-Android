package com.urlxl.mail

import android.content.Context
import com.urlxl.mail.pgp.PgpBootstrapClient
import com.urlxl.mail.pgp.PgpBootstrapResult
import com.urlxl.mail.pgp.PgpComposeState
import com.urlxl.mail.pgp.RecipientKeyClient
import com.urlxl.mail.pgp.RecipientKeyResult
import com.urlxl.mail.pgp.pgpComposeStateOf
import com.urlxl.mail.push.PairingData
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory

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
) {

    /**
     * Which PGP controls this account gets. Cached for the process on success only — caching a
     * failure would disable encryption for the rest of the session over one flaky request.
     *
     * Returns the everything-hidden state when the device is not paired or bootstrap fails:
     * couldn't-check is not "no".
     */
    suspend fun composeState(): PgpComposeState {
        cachedState?.let { return it }
        val pairing = pairingProvider()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            return pgpComposeStateOf(hasIdentity = null, protection = null)
        }
        return when (val result = bootstrapClient.fetch(pairing.serverUrl, deviceId, deviceSecret)) {
            is PgpBootstrapResult.Success ->
                pgpComposeStateOf(result.hasIdentity, result.protection).also { cachedState = it }
            is PgpBootstrapResult.Failed -> pgpComposeStateOf(hasIdentity = null, protection = null)
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
        val pairing = pairingProvider()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return emptyList()
        return when (val result = recipientKeyClient.check(pairing.serverUrl, deviceId, deviceSecret, addresses)) {
            is RecipientKeyResult.Success -> result.keyless
            is RecipientKeyResult.Failed -> emptyList()
        }
    }

    companion object {
        /** Process-scoped, so a second compose in the same session costs no round trip. Not
         *  persisted: custody mode is fixed at key creation, but a re-pair to a different account
         *  restarts the process anyway (see AppRestart). */
        @Volatile
        private var cachedState: PgpComposeState? = null

        fun resetSessionCache() {
            cachedState = null
        }

        /** Wires the real, TLS-pinned clients. Mirrors [com.urlxl.mail.pgp.hasPgpIdentity]'s
         *  Context-based default. */
        fun from(context: Context): ComposePgpController = ComposePgpController(
            pairingProvider = { PushRuntime.graph(context).repository.pairingForAuthenticatedCall() },
            bootstrapClient = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(context)),
            recipientKeyClient = RecipientKeyClient(callFactory = pinnedPairingCallFactory(context)),
        )
    }
}
