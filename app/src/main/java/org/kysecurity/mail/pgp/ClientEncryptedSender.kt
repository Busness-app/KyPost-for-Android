package org.kysecurity.mail.pgp

import org.kysecurity.mail.mail.ClientEncryptedDelivery
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import java.time.OffsetDateTime
import java.time.ZoneOffset

/** Discovery found a key whose fingerprint does not match the one pinned to that contact. */
private const val TIER_KEY_CHANGED = "key_changed"

/**
 * Every way a client-encrypted send can end. One per row of the compose screen's exit table.
 *
 * Separate objects rather than one error string because the UI shows a different sentence — and
 * sometimes a different button — for each. [Cancelled] in particular is not an error: the user
 * dismissed a prompt they raised, and the screen simply goes back to offering Send.
 */
internal sealed class ClientSendOutcome {
    data class Sent(val sentSaved: Boolean, val warning: String) : ClientSendOutcome()

    object Cancelled : ClientSendOutcome()
    object NotEnrolled : ClientSendOutcome()
    object NoSecureLockScreen : ClientSendOutcome()
    data class UnsealFailed(val message: String) : ClientSendOutcome()

    /** The account is not client-protected after all, so this is the wrong send path entirely. */
    object NotClientProtected : ClientSendOutcome()

    /** No mail account configured, so no valid `From` can be built. */
    object NoAccountAddress : ClientSendOutcome()

    /** A pinned key's fingerprint no longer matches what discovery returned. Deliberately distinct
     *  from [KeysMissing] and checked before it — see the KDoc on the check itself. */
    data class KeyChanged(val addresses: List<String>) : ClientSendOutcome()

    data class KeysMissing(val addresses: List<String>) : ClientSendOutcome()
    data class TooManyRecipients(val message: String) : ClientSendOutcome()
    data class ResolveFailed(val message: String) : ClientSendOutcome()
    data class EncryptFailed(val message: String) : ClientSendOutcome()
    data class SendFailed(val outcome: MailOutcome<*>) : ClientSendOutcome()
}

/** Recipient key lookup, behind an interface so this orchestrator takes no dependency on OkHttp,
 *  pairing credentials or a `Context`. */
internal fun interface RecipientKeyResolver {
    suspend fun resolve(addresses: List<String>): ResolveResult
}

/** The relay hop. Blocking, matching the rest of `MailSource`. */
internal fun interface ClientEncryptedTransport {
    fun send(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome>
}

/**
 * Encrypts and signs one message on this device, then hands the ciphertext to the relay.
 *
 * **No Android imports**, following [EncryptedMessageReader] — which is what lets the whole exit
 * table be a JVM test with fakes instead of an instrumented one.
 *
 * Nothing here decides whether the account *may* use this path; [pgpComposeStateOf] does that. This
 * runs only once that decision is made.
 */
internal class ClientEncryptedSender(
    private val opener: VaultOpener,
    private val resolver: RecipientKeyResolver,
    private val transport: ClientEncryptedTransport,
    /** The address every delivery's `From` must carry, from `GET /api/pgp/bootstrap`'s
     *  `suggestedUserIDs[0]`. The relay compares each delivery's own header against it and answers
     *  403 on a mismatch. */
    private val accountAddress: String,
    private val now: () -> OffsetDateTime = { OffsetDateTime.now(ZoneOffset.UTC) },
    private val boundaryToken: () -> String = ::randomBoundaryToken,
) {

    suspend fun send(draft: MailDraft, sign: Boolean): ClientSendOutcome {
        val from = accountAddress.trim()
        if (from.isEmpty()) return ClientSendOutcome.NoAccountAddress

        val fields = splitRecipientFields(draft.to, draft.cc, draft.bcc)
        val addresses = fields.to + fields.cc + fields.bcc

        // Resolve BEFORE unlocking. A send that was going to be refused anyway must not interrupt
        // the user for a biometric they gain nothing from. (The web client prompts first; this is a
        // deliberate divergence, not an oversight.)
        val resolved = when (val result = resolver.resolve(addresses)) {
            is ResolveResult.Success -> result.results
            is ResolveResult.NotClientProtected -> return ClientSendOutcome.NotClientProtected
            is ResolveResult.TooMany -> return ClientSendOutcome.TooManyRecipients(result.message)
            is ResolveResult.Failed -> return ClientSendOutcome.ResolveFailed(result.message)
        }
        val byAddress = resolved.associateBy { it.address.lowercase() }

        // A broken pin outranks a missing key, and is checked first. `key_changed` means discovery
        // found a key whose fingerprint does not match the pinned one — which is what a rotation
        // looks like and also what interception looks like. Folding it into "no key on file" tells
        // the user nothing changed at the exact moment the one thing worth telling them did.
        val changed = addresses.filter { byAddress[it.lowercase()]?.tier == TIER_KEY_CHANGED }
        if (changed.isNotEmpty()) return ClientSendOutcome.KeyChanged(changed)

        val missing = addresses.filter {
            val key = byAddress[it.lowercase()]
            key == null || !key.usable || key.publicKey.isBlank()
        }
        // There is no pickup fallback on this path and there must not be: the server-side one works
        // by storing the plaintext, which is the thing client-side protection exists to prevent.
        if (missing.isNotEmpty()) return ClientSendOutcome.KeysMissing(missing)

        if (!EnrollmentSession.isHeld()) {
            when (val outcome = opener.open()) {
                is OpenOutcome.Opened -> Unit
                is OpenOutcome.Cancelled -> return ClientSendOutcome.Cancelled
                is OpenOutcome.NotEnrolled -> return ClientSendOutcome.NotEnrolled
                is OpenOutcome.NoSecureLockScreen -> return ClientSendOutcome.NoSecureLockScreen
                is OpenOutcome.Failed -> return ClientSendOutcome.UnsealFailed(outcome.message)
            }
        }
        // Re-read rather than trusting the branch above: the app can lock between the unseal and
        // here, and lockNow() clears this holder. Same reasoning as EncryptedMessageReader.
        val privateKey = EnrollmentSession.peek() ?: return ClientSendOutcome.NotEnrolled

        // Built once and shared by every delivery and the Sent copy, so no recipient can receive a
        // subtly different message from another.
        val protectedContent = buildProtectedContent(
            contentType = "${draft.mode.ifBlank { "html" }.asContentType()}; charset=utf-8",
            body = draft.body,
            subject = draft.subject,
            attachments = draft.attachments.map {
                OutgoingMimeAttachment(name = it.name, mimeType = it.mimeType, dataBase64 = it.dataBase64)
            },
            boundaryToken = boundaryToken,
        ).toByteArray(Charsets.UTF_8)

        val date = rfc5322Date(now())
        val signingKey = privateKey.takeIf { sign }

        // To and CC share one ciphertext; each BCC gets their own, so no BCC recipient's key id
        // appears in a packet another recipient can read.
        val groups = buildList {
            val shared = fields.to + fields.cc
            if (shared.isNotEmpty()) add(shared)
            fields.bcc.forEach { add(listOf(it)) }
        }

        val deliveries = groups.map { recipients ->
            val keys = recipients.mapNotNull { byAddress[it.lowercase()]?.publicKey }
            val encrypted = PgpEncryptor.encrypt(protectedContent, keys, signingKey)
            if (encrypted !is EncryptResult.Ok) {
                return ClientSendOutcome.EncryptFailed((encrypted as EncryptResult.Failed).message)
            }
            ClientEncryptedDelivery(
                recipients = recipients,
                ciphertext = wrapAsPgpMime(
                    envelope = OutgoingEnvelope(from = from, to = fields.to, cc = fields.cc, date = date),
                    armoredMessage = encrypted.armored,
                    boundaryToken = boundaryToken,
                ),
            )
        }

        // Encrypted to the public half of the key we just unsealed, never to anything the server
        // supplied. A hostile server handing back "your" public key would otherwise get a readable
        // copy of every message sent, with nothing on screen looking any different.
        val ownKey = PgpEncryptor.ownPublicKey(privateKey)
            ?: return ClientSendOutcome.EncryptFailed("could not derive this account's own key")
        val sentCopy = PgpEncryptor.encrypt(protectedContent, listOf(ownKey), signingKey)
        if (sentCopy !is EncryptResult.Ok) {
            return ClientSendOutcome.EncryptFailed((sentCopy as EncryptResult.Failed).message)
        }

        val outcome = transport.send(
            ClientEncryptedMessage(
                from = from,
                to = fields.to,
                cc = fields.cc,
                bcc = fields.bcc,
                deliveries = deliveries,
                sentCopy = wrapAsPgpMime(
                    envelope = OutgoingEnvelope(from = from, to = fields.to, cc = fields.cc, date = date),
                    armoredMessage = sentCopy.armored,
                    boundaryToken = boundaryToken,
                ),
                mode = draft.mode.ifBlank { "html" },
            ),
        )
        return when (outcome) {
            is MailOutcome.Success -> ClientSendOutcome.Sent(outcome.value.sentSaved, outcome.value.warning)
            else -> ClientSendOutcome.SendFailed(outcome)
        }
    }

    private fun String.asContentType(): String = if (equals("plain", ignoreCase = true)) "text/plain" else "text/html"
}
