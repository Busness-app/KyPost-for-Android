# Security audit — KyPost Android, run 7

## Summary

The reviewed IPC and WebView surfaces have effective current barriers: exported components are thin,
sensitive screens are non-exported, attachment grants are one-shot, notification payloads are
immutable, and untrusted HTML is rendered without JavaScript or automatic network access. The new
on-device PGP reader does introduce one confirmed denial-of-service path: compressed OpenPGP data
is expanded without a decompressed-size limit before integrity verification.

## Prior coverage

Runs 1–6 already documented the earlier pairing, redirect, WebView quote/navigation, attachment,
MFA, wipe/unpair, enrollment, and signature issues. They are intentionally not repeated here.

## Finding

| Severity | Finding |
|---|---|
| MEDIUM | Unbounded OpenPGP decompression can kill the client on decrypt |

### MEDIUM — Unbounded OpenPGP decompression can kill the client on decrypt

Attacker: an email sender who can deliver an OpenPGP message encrypted to the victim's public key.
The sender supplies a valid compressed OpenPGP literal whose compressed representation is within the
relay/client response limit but whose expanded plaintext is much larger. When the victim taps
Decrypt, `PgpDecryptor.readLiteral` copies the decompressed stream into an unbounded
`ByteArrayOutputStream`; the process can exhaust its heap and crash. This is a client availability
failure, not a confidentiality or authentication bypass.

Trace: `PgpPayloadClient.fetch` reads the authenticated payload through the shared 32 MiB response
cap; `EncryptedMessageReader.read` calls `PgpDecryptor.decrypt`; `PgpDecryptor.readLiteral` calls
`obj.inputStream.copyTo(out)` without a maximum and only later returns to the integrity check.

Fix: enforce a maximum decompressed plaintext size while copying the literal stream, aborting with a
bounded `DecryptResult.Failed`/`ReadOutcome.TooLarge` result. Apply the same bound to any subsequent
MIME parsing input.

## Hardening notes (not findings)

- The relay response cap is useful but does not substitute for a decompressed-output cap.
- Attachment viewer apps receive bytes only through the non-exported provider with an explicit,
  one-time read grant; user-selected viewing is an intentional trust transfer.
- The exported launcher accepts external starts, but routes only to non-exported app screens and does
  not forward MFA or pairing credentials.

## Positive patterns

- `followRedirects(false)` and `followSslRedirects(false)` protect custom device-secret headers.
- EmailDetail uses an opaque `loadDataWithBaseURL(null, ...)` origin and disables script, file/content
  access, DOM storage, and network loads by default.
- Compose quotes are parser-sanitized before entering the JavaScript editor bridge.
- MFA approval and pairing confirmation are kept behind non-exported activities and explicit user
  interaction.
