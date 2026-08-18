package org.kysecurity.mail.pgp

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

    /** The server has the message but it carries no OpenPGP payload (404). Terminal — unlike a
     *  transport failure, retrying cannot change it, so the UI must not offer Retry. Reachable when
     *  the inbox flag said encrypted and the fetched message disagrees. */
    object NoEncryptedContent : ReadOutcome()

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
        /** The sender exactly as displayed. Display context only — deliberately unread by this
         *  function. The signature binding is the SERVER's job: it narrows `payload.signerKeys` to
         *  the resolved sender before this ever runs (see the `offeredKeys` comment below), so this
         *  reader has no binding decision left to make with it. Do not "wire this up" to filter
         *  `signerKeys` — that reintroduces the client-side From parser an earlier task deleted
         *  after it diverged from the server's on 27 of 111 adversarial headers. Kept as a parameter
         *  because callers already have it and a future caller may want it for a purpose that is
         *  NOT the signature verdict (e.g. logging, or comparing against `resolvedSender` for
         *  display). */
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
        //
        if (!EnrollmentSession.isHeld()) return ReadOutcome.NeedsUnlock

        val payload = when (val result = payloads.fetch(mailbox, messageId)) {
            is PgpPayloadResult.Success -> result
            is PgpPayloadResult.TooLarge -> return ReadOutcome.TooLarge
            is PgpPayloadResult.NotClientProtected -> return ReadOutcome.NotClientProtected
            is PgpPayloadResult.NoPayload -> return ReadOutcome.NoEncryptedContent
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
        // This filter cannot change today's ReadOutcome: signatureStateFor returns KEY_CHANGED for
        // any SIGNED message the moment ANY entry in `payload.signerKeys` has `conflict = true` —
        // checked after `!present -> NONE` and `signerKeys.isEmpty() -> SIGNER_UNKNOWN`, but still
        // before it ever looks at what got offered here or whether the signature matched — so no
        // test can observe this line doing anything (confirmed:
        // EncryptedMessageReaderTest.aConflictedKeyYieldsKeyChanged still passes with this filter
        // deliberately removed). It stays anyway, as defence-in-depth against exactly one plausible
        // future edit: someone reordering signatureStateFor so conflict no longer short-circuits
        // first. If that ever happens, offering a key that failed its TOFU pin would start to
        // matter, and deleting this filter now would make that future edit silently unsafe. Do not
        // delete this as "dead code" without re-checking signatureStateFor's precedence first.
        val offeredKeys = payload.signerKeys.filter { !it.conflict }.map { it.publicKey }

        // A signed-but-not-encrypted message arrives with a readable body and a detached
        // signature; there is nothing to decrypt.
        //
        // UNREACHABLE IN PRODUCTION TODAY. This function, attemptDecrypt(), is only invoked from
        // EmailDetailActivity's PgpMessageState.CLIENT_PROTECTED branch, and pgpMessageStateOf()
        // only reaches CLIENT_PROTECTED when the server's own pgpEncrypted flag is true — a
        // signed-only message never sets it, and the server keeps the two payloads mutually
        // exclusive (see signedOnlyBody in pgp_client_read.go, which zeroes the body whenever
        // encryptedPayload is non-empty and vice versa). So payload.encryptedPayload.isBlank() has
        // no live caller that can make it true.
        //
        // Do not delete it and do not try to make it work — reviving it is a design decision for
        // the owner, not a cleanup. If it IS revived: payload.body here is signedOnlyBody's
        // enmime-extracted DISPLAY body, not the canonical octets that were actually signed —
        // pgp_client_read.go's own comment on verifySignedOnlyMessageContent documents that a
        // canonicalization mismatch there is routine and just leaves PGPVerified false rather than
        // erroring. verifyDetached below has no such tolerance: a body that reads identically to a
        // human but differs byte-for-byte from what was signed fails verification outright, and
        // signatureStateFor maps a bound sender plus an unverifiable signature to INVALID — the
        // strongest accusation this app renders. Reviving this path with payload.body as-is would
        // therefore falsely accuse real correspondents of a bad signature on a routine, expected
        // mismatch. It would need the canonical signed octets, not the display body, before it can
        // safely run.
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
                // This IS "whichever non-conflicted contact sorts first" — it looks like the exact
                // thing the comment above forbids, but it is not the binding decision: nothing
                // that key id verified against feeds the verdict below. This fallback only exists
                // to produce a non-null RawSignature (present = true, valid = false, some
                // signerKeyId) when every real candidate above failed, so signatureStateFor can
                // still run its own key-id re-match against payload.signerKeys and land on
                // SIGNER_UNKNOWN or INVALID rather than crash on a null. The sender binding is
                // enforced there, not by which key was armored here.
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
            signatureStateFor(decrypted.signature, payload.signerKeys),
            payload.resolvedSender,
        )
    }
}
