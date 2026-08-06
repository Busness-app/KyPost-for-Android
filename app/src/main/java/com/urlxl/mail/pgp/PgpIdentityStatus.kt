package com.urlxl.mail.pgp

import android.content.Context
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory

/** Maps a [PgpQrTokenResult] (from [PgpQrClient.mintToken]) to "does this account have a PGP
 *  identity" — `true`/`false` are definitive answers, `null` means the question couldn't be
 *  answered (not paired, network error, server error) and callers should leave whatever they were
 *  already showing alone rather than treating "couldn't check" as "no". Pulled out as its own pure
 *  function so it's unit-testable without a Context/PushRuntime dependency. */
internal fun pgpIdentityFromMintResult(result: PgpQrTokenResult): Boolean? = when (result) {
    is PgpQrTokenResult.Success -> true
    is PgpQrTokenResult.NoIdentity -> false
    else -> null
}

/**
 * Whether the currently paired account has a PGP identity configured on the server.
 *
 * There is no device-reachable "just tell me yes/no" endpoint for this: `GET /api/pgp/identity`
 * (kypost-server's actual identity-status endpoint) is registered `withAuth` — web-session-cookie
 * only, per `backend/internal/api/server.go` — so a paired mobile device, which authenticates with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret headers and has no session cookie (see
 * [PgpQrClient]'s own doc comment), can't call it. Minting a PGP QR token
 * (`GET /api/pgp/qr/token`, `withMailAuth` — reachable from a paired device) already distinguishes
 * "has an identity" (200) from "doesn't" (400 → [PgpQrTokenResult.NoIdentity]) as a side effect of
 * its real job, and [PgpKeyActivity] already relies on exactly that distinction to decide what to
 * show on its own-QR screen — this reuses the same signal rather than adding a second,
 * device-unreachable way to ask the same question.
 *
 * Returns `null` (not "no") when the account isn't paired or the check fails for any other reason,
 * so callers don't have to treat "couldn't check" the same as a confirmed "no identity".
 */
suspend fun hasPgpIdentity(
    context: Context,
    client: PgpQrClient = PgpQrClient(callFactory = pinnedPairingCallFactory(context)),
): Boolean? {
    val pairing = PushRuntime.graph(context).repository.pairingForAuthenticatedCall()
    val deviceId = pairing?.deviceId
    val deviceSecret = pairing?.deviceSecret
    if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return null
    return pgpIdentityFromMintResult(client.mintToken(pairing.serverUrl, deviceId, deviceSecret))
}

/**
 * The account's own PGP fingerprint, computed locally from the public key `GET /api/pgp/bootstrap`
 * returned, or null when the account has no identity, the key doesn't parse, or the call failed.
 *
 * The obvious-looking local source — the self-contact's `pgpKey` column — is the wrong one and is
 * why [PgpKeyActivity] used to tell every user their fingerprint was unavailable: that column is an
 * ordinary contact field, written only when a key is attached to a contact by hand or by the QR
 * scan, with no connection to the account's real PGP identity (see
 * [com.urlxl.mail.contacts.contactHasLinkedPgpKey], which exists for the same reason). The identity
 * itself lives server-side, and bootstrap is the only route a paired device has to it.
 *
 * Hashing those bytes rather than reading the response's `fingerprint` field is the same rule
 * [PgpKeyActivity.showFetchedKey] follows for the other party's key: a fingerprint the user is
 * about to read aloud must describe the key material actually in hand.
 */
internal fun ownFingerprintFromBootstrap(result: PgpBootstrapResult): String? = when (result) {
    is PgpBootstrapResult.Success -> result.publicKey.takeIf { it.isNotBlank() }
        ?.let { PgpFingerprint.compute(it) }
    is PgpBootstrapResult.Failed -> null
}
