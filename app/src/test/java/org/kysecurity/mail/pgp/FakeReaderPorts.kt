package org.kysecurity.mail.pgp

internal class FakeVaultOpener(
    var outcome: OpenOutcome = OpenOutcome.Opened,
    var keyToHold: String? = TestPgpPrivateKey.ARMORED_PRIVATE,
) : VaultOpener {
    var opened = 0
    override suspend fun open(): OpenOutcome {
        opened++
        if (outcome is OpenOutcome.Opened) keyToHold?.let { EnrollmentSession.put(it.toCharArray()) }
        return outcome
    }
}

internal class FakePayloadSource(var result: PgpPayloadResult) : PayloadSource {
    var fetched = 0
    override suspend fun fetch(mailbox: String, messageId: String): PgpPayloadResult {
        fetched++
        return result
    }
}

/** Defaults to ARMORED_MIME_MESSAGE: ARMORED_MESSAGE's plaintext has no MIME headers to parse. */
internal fun successPayload(
    encrypted: String = TestPgpPrivateKey.ARMORED_MIME_MESSAGE,
    signerKeys: List<SignerKey> = emptyList(),
    sender: String = "bob@example.com",
    resolvedSender: String = "bob@example.com",
) = PgpPayloadResult.Success(
    encryptedPayload = encrypted,
    signaturePayload = "",
    body = "",
    signerKeys = signerKeys,
    sender = sender,
    resolvedSender = resolvedSender,
)

/** Signed but not encrypted: blank `encryptedPayload`, readable `body`, a detached signature. */
internal fun detachedSignedPayload(
    body: String = TestPgpPrivateKey.DETACHED_SIGNATURE_BODY,
    signaturePayload: String = TestPgpPrivateKey.ARMORED_DETACHED_SIGNATURE,
    signerKeys: List<SignerKey> = emptyList(),
    sender: String = "bob@example.com",
    resolvedSender: String = "bob@example.com",
) = PgpPayloadResult.Success(
    encryptedPayload = "",
    signaturePayload = signaturePayload,
    body = body,
    signerKeys = signerKeys,
    sender = sender,
    resolvedSender = resolvedSender,
)
