package com.urlxl.mail.pgp

/**
 * The ciphertext source, behind an interface so the orchestrator takes no dependency on OkHttp,
 * pairing credentials or a `Context`.
 */
internal interface PayloadSource {
    suspend fun fetch(mailbox: String, messageId: String): PgpPayloadResult
}

/**
 * Every way reading an encrypted message can end. One per row of the design spec's exit table.
 *
 * They are separate objects rather than one error string because the UI shows a different sentence,
 * and sometimes a different button, for each. [Cancelled] in particular is not an error: the user
 * dismissed a sheet they raised, and the screen simply goes back to offering the Decrypt button.
 */
internal sealed class ReadOutcome {
    data class Decrypted(
        val body: DecryptedBody,
        val signature: PgpSignatureState,
        /** The mailbox the SERVER resolved from the From header, and the one the verdict is about.
         *  Rendered in place of the raw sender wherever a verdict is shown — the two are separable
         *  by an attacker. Empty when the server could not resolve one. */
        val resolvedSender: String,
    ) : ReadOutcome()

    /** The key is not held and this call was not allowed to prompt. The screen offers Decrypt. */
    object NeedsUnlock : ReadOutcome()

    object Cancelled : ReadOutcome()
    object NotEnrolled : ReadOutcome()
    object NoSecureLockScreen : ReadOutcome()
    object TooLarge : ReadOutcome()
    object NotClientProtected : ReadOutcome()
    data class UnsealFailed(val message: String) : ReadOutcome()
    data class FetchFailed(val message: String) : ReadOutcome()
    data class DecryptFailed(val message: String) : ReadOutcome()
}

/**
 * Reads one client-protected message: unseal if needed, fetch, decrypt, bind the signature, parse.
 *
 * **No Android imports**, following [EnrollmentCeremony] — which is what lets the whole exit table
 * be a JVM test with fakes instead of an instrumented one.
 *
 * The decrypted body is returned to the caller and never persisted. See the design spec's
 * non-negotiable rules: it must not reach Room, and must not reach `fetchedBodyHtml`.
 */
internal class EncryptedMessageReader(
    private val opener: VaultOpener,
    private val payloads: PayloadSource,
) {

    suspend fun read(
        mailbox: String,
        messageId: String,
        /** The sender exactly as displayed, so the binding is checked against what the user sees. */
        sender: String,
        /** False on an automatic attempt when the screen opens; true when the user tapped Decrypt.
         *  This is what keeps the biometric sheet tied to a deliberate action. */
        unlockIfNeeded: Boolean,
    ): ReadOutcome {
        if (EnrollmentSession.peek() == null) {
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
        val key = EnrollmentSession.peek() ?: return ReadOutcome.NeedsUnlock

        val payload = when (val result = payloads.fetch(mailbox, messageId)) {
            is PgpPayloadResult.Success -> result
            is PgpPayloadResult.TooLarge -> return ReadOutcome.TooLarge
            is PgpPayloadResult.NotClientProtected -> return ReadOutcome.NotClientProtected
            is PgpPayloadResult.NoPayload -> return ReadOutcome.FetchFailed("this message carries no encrypted content")
            is PgpPayloadResult.Failed -> return ReadOutcome.FetchFailed(result.message)
        }

        // `payload.signerKeys` arrives ALREADY narrowed to the displayed sender by the server (Task
        // 14's `boundSignerKeysForSender`). Do not re-narrow here, and do not parse `sender` to do
        // it: a second parser deciding the same binding is exactly the defect an earlier task
        // removed — the client's own From parser diverged from the server's on 27 of 111
        // adversarial headers, including RFC 5322 comments, which let any contact forge a verified
        // badge for anyone.
        //
        // Conflicted keys are still dropped here: they carry no key material and must never be
        // offered to a signature check. They stay in `payload.signerKeys` so `signatureStateFor`
        // can report KEY_CHANGED.
        //
        // This filter cannot change today's ReadOutcome: signatureStateFor returns KEY_CHANGED the
        // moment ANY entry in `payload.signerKeys` has `conflict = true`, before it ever looks at
        // what got offered here or whether the signature matched — so no test can observe this line
        // doing anything (confirmed: EncryptedMessageReaderTest.aConflictedKeyYieldsKeyChanged
        // still passes with this filter deliberately removed). It stays anyway, as defence-in-depth
        // against exactly one plausible future edit: someone reordering signatureStateFor so
        // conflict no longer short-circuits first. If that ever happens, offering a key that failed
        // its TOFU pin would start to matter, and deleting this filter now would make that future
        // edit silently unsafe. Do not delete this as "dead code" without re-checking
        // signatureStateFor's precedence first.
        val offeredKeys = payload.signerKeys.filter { !it.conflict }.map { it.publicKey }

        // A signed-but-not-encrypted message arrives with a readable body and a detached
        // signature; there is nothing to decrypt.
        //
        // The offered key is narrowed to the displayed sender here too. Taking "whichever
        // non-conflicted contact sorts first" would fail verification for a genuine
        // detached-signed message from anyone else — and signatureStateFor maps a bound sender
        // plus an unverifiable signature to INVALID, which tells the user to treat a legitimate
        // correspondent's message as untrusted. Same narrowing rule as the encrypted path above,
        // for the same reason.
        if (payload.encryptedPayload.isBlank()) {
            val raw = offeredKeys.firstNotNullOfOrNull { armored ->
                PgpDecryptor.verifyDetached(
                    armoredPublicKey = armored,
                    body = payload.body.toByteArray(Charsets.UTF_8),
                    armoredSignature = payload.signaturePayload,
                ).takeIf { it.valid }
            } ?: PgpDecryptor.verifyDetached(
                armoredPublicKey = offeredKeys.firstOrNull().orEmpty(),
                body = payload.body.toByteArray(Charsets.UTF_8),
                armoredSignature = payload.signaturePayload,
            )
            val parsed = PgpMimeReader.read(payload.body.toByteArray(Charsets.UTF_8))
                ?: DecryptedBody(html = null, plain = payload.body, protectedSubject = null)
            return ReadOutcome.Decrypted(
                parsed,
                signatureStateFor(raw, payload.signerKeys),
                payload.resolvedSender,
            )
        }

        val decrypted = when (
            val result = PgpDecryptor.decrypt(key, payload.encryptedPayload, offeredKeys)
        ) {
            is DecryptResult.Ok -> result
            // Deliberately does NOT clear EnrollmentSession: one message failing says nothing
            // about the held key, and clearing would re-prompt for every later message.
            is DecryptResult.Failed -> return ReadOutcome.DecryptFailed(result.message)
        }

        val body = PgpMimeReader.read(decrypted.plaintext)
            ?: return ReadOutcome.DecryptFailed("this message could not be read once decrypted")

        return ReadOutcome.Decrypted(
            body,
            signatureStateFor(decrypted.signature, payload.signerKeys),
            payload.resolvedSender,
        )
    }
}
