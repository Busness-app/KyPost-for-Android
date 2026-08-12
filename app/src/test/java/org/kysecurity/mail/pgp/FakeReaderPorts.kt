package org.kysecurity.mail.pgp

internal class FakeVaultOpener(
    var outcome: OpenOutcome = OpenOutcome.Opened,
    var keyToHold: String? = TestPgpPrivateKey.ARMORED_PRIVATE,
) : VaultOpener {
    var opened = 0
    override suspend fun open(): OpenOutcome {
        opened++
        if (outcome is OpenOutcome.Opened) keyToHold?.let { EnrollmentSession.put(it) }
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

/** `PgpPayloadResult.Success` has no default values for any field, so every fixture that stands in
 *  for a fetched payload goes through here rather than constructing `Success` directly. `sender` and
 *  `resolvedSender` default to the same address the tests' own `read()` helper defaults `sender` to,
 *  since production always has the server compute both from the same message.
 *
 *  Defaults to [TestPgpPrivateKey.ARMORED_MIME_MESSAGE], not [TestPgpPrivateKey.ARMORED_MESSAGE]:
 *  the latter's plaintext is bare text with no MIME headers, so [PgpMimeReader] can never parse it
 *  and every test that needs the reader to actually reach `Decrypted` would fail past decryption. */
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

/** A signed-but-not-encrypted payload: `encryptedPayload` blank, `body` readable,
 *  `signaturePayload` a detached signature over it — the shape `PgpPayloadClient` returns for
 *  RFC 3156 clear-signed mail. Defaults to [TestPgpPrivateKey.DETACHED_SIGNATURE_BODY] signed by
 *  [TestPgpPrivateKey.ARMORED_DETACHED_SIGNATURE], both verified independently with `gpg --verify`
 *  before being wired in here, so `EncryptedMessageReader`'s `payload.encryptedPayload.isBlank()`
 *  branch has a real fixture to run against instead of never executing at all (it previously had
 *  none — `successPayload` always sets a non-blank `encryptedPayload`). */
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
