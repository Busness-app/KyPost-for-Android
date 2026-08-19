package org.kysecurity.mail.pgp

/** The ciphertext source, behind an interface so the orchestrator takes no Android dependency. */
internal interface PayloadSource {
    suspend fun fetch(mailbox: String, messageId: String): PgpPayloadResult
}

/** Every way reading an encrypted message can end. One per row of the spec's exit table. */
internal sealed class ReadOutcome {
    data class Decrypted(
        val body: DecryptedBody,
        val signature: PgpSignatureState,
        /** The mailbox the SERVER resolved from the From header, and the one the verdict is about.
         *  Rendered in place of the raw sender wherever a verdict is shown — the two are separable
         *  by an attacker. Empty when the server could not resolve one. */
        val resolvedSender: String,
    ) : ReadOutcome() {
        /** Redacted: the body is a decrypted message. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Decrypted(redacted)"
    }

    /** The key is not held and this call was not allowed to prompt. The screen offers Decrypt. */
    object NeedsUnlock : ReadOutcome()

    object Cancelled : ReadOutcome()
    object NotEnrolled : ReadOutcome()
    object NoSecureLockScreen : ReadOutcome()
    object TooLarge : ReadOutcome()
    object NotClientProtected : ReadOutcome()

    /** The server has the message but it carries no OpenPGP payload (404). Terminal — unlike a
     *  transport failure, retrying cannot change it, so the UI must not offer Retry. Reachable when
     *  the inbox flag said encrypted and the fetched message disagrees. */
    object NoEncryptedContent : ReadOutcome()

    data class UnsealFailed(val message: String) : ReadOutcome()
    data class FetchFailed(val message: String) : ReadOutcome()
    data class DecryptFailed(val message: String) : ReadOutcome()
}

/** Reads one client-protected message. No Android imports; the decrypted body is never stored. */
internal class EncryptedMessageReader(
    private val opener: VaultOpener,
    private val payloads: PayloadSource,
    /** This device's own answer to "whose key is this". Empty by default: the verdict caps lower. */
    private val localSignerKeys: LocalSignerKeyLookup = LocalSignerKeyLookup { emptyList() },
) {

    suspend fun read(
        mailbox: String,
        messageId: String,
        /** Display only, deliberately unread. Do not wire into the signature verdict; the server binds. */
        sender: String,
        /** False on an automatic attempt when the screen opens; true when the user tapped Decrypt.
         *  This is what keeps the biometric sheet tied to a deliberate action. */
        unlockIfNeeded: Boolean,
    ): ReadOutcome {
        if (!EnrollmentSession.isHeld()) {
            if (!unlockIfNeeded) return ReadOutcome.NeedsUnlock
            when (val outcome = opener.open()) {
                is OpenOutcome.Opened -> Unit
                is OpenOutcome.Cancelled -> return ReadOutcome.Cancelled
                is OpenOutcome.NotEnrolled -> return ReadOutcome.NotEnrolled
                is OpenOutcome.NoSecureLockScreen -> return ReadOutcome.NoSecureLockScreen
                is OpenOutcome.Failed -> return ReadOutcome.UnsealFailed(outcome.message)
            }
        }
        // Re-read rather than trusting the branch above: the app can lock between the unseal and
        // here, and lockNow() clears this holder.
        if (!EnrollmentSession.isHeld()) return ReadOutcome.NeedsUnlock

        val payload = when (val result = payloads.fetch(mailbox, messageId)) {
            is PgpPayloadResult.Success -> result
            is PgpPayloadResult.TooLarge -> return ReadOutcome.TooLarge
            is PgpPayloadResult.NotClientProtected -> return ReadOutcome.NotClientProtected
            is PgpPayloadResult.NoPayload -> return ReadOutcome.NoEncryptedContent
            is PgpPayloadResult.Failed -> return ReadOutcome.FetchFailed(result.message)
        }

        // The local answer, resolved first: a relay that lies about the address gets a lookup miss.
        val localKeys = runCatching { localSignerKeys.keysFor(payload.resolvedSender) }
            .getOrDefault(emptyList())

        // The server already narrowed signerKeys to the sender — do not re-narrow. Local keys go first.
        val offeredKeys =
            localKeys.map { it.publicKey } + payload.signerKeys.filter { !it.conflict }.map { it.publicKey }

        // Signed-but-not-encrypted. Unreachable today; do not revive without the canonical signed octets.
        if (payload.encryptedPayload.isBlank()) {
            val raw = offeredKeys.firstNotNullOfOrNull { armored ->
                PgpDecryptor.verifyDetached(
                    armoredPublicKey = armored,
                    body = payload.body.toByteArray(Charsets.UTF_8),
                    armoredSignature = payload.signaturePayload,
                ).takeIf { it.valid }
            } ?: PgpDecryptor.verifyDetached(
                // Not the binding decision: this only yields a non-null RawSignature so the verdict can run.
                armoredPublicKey = offeredKeys.firstOrNull().orEmpty(),
                body = payload.body.toByteArray(Charsets.UTF_8),
                armoredSignature = payload.signaturePayload,
            )
            val parsed = PgpMimeReader.read(payload.body.toByteArray(Charsets.UTF_8))
                ?: DecryptedBody(html = null, plain = payload.body, protectedSubject = null)
            return ReadOutcome.Decrypted(
                parsed,
                signatureStateFor(raw, payload.signerKeys, localKeys),
                payload.resolvedSender,
            )
        }

        // The key never leaves the holder's CharArray: withKey scopes it to this one call. Null
        // means the app locked between the check above and here, which is NeedsUnlock, not a
        // decryption failure.
        val result = EnrollmentSession.withKey { key ->
            PgpDecryptor.decrypt(key, payload.encryptedPayload, offeredKeys)
        } ?: return ReadOutcome.NeedsUnlock

        val decrypted = when (result) {
            is DecryptResult.Ok -> result
            // Deliberately does NOT clear EnrollmentSession: one message failing says nothing
            // about the held key, and clearing would re-prompt for every later message.
            is DecryptResult.Failed -> return ReadOutcome.DecryptFailed(result.message)
        }

        val body = PgpMimeReader.read(decrypted.plaintext)
            ?: return ReadOutcome.DecryptFailed("this message could not be read once decrypted")

        return ReadOutcome.Decrypted(
            body,
            signatureStateFor(decrypted.signature, payload.signerKeys, localKeys),
            payload.resolvedSender,
        )
    }
}
