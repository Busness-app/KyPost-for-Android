# Finding detail

## Unbounded OpenPGP decompression can kill the client on decrypt — MEDIUM

Attacker and action: a sender creates a valid OpenPGP message encrypted to the victim's public key,
using compression to make a highly repetitive MIME body fit within the relay's response limit. The
sender delivers it to the victim. The victim taps the client-side Decrypt action.

Data flow:

1. `app/src/main/java/com/urlxl/mail/pgp/PgpPayloadClient.kt:105-106`, `fetch`, obtains the payload
   through the shared HTTP client. `BodySizeLimitInterceptor` limits encoded response bytes to 32 MiB,
   but does not limit decompressed OpenPGP output.
2. `app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt:189-190`, `read`, passes the
   attacker-controlled armored encrypted payload to `PgpDecryptor.decrypt`.
3. `app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt:149-169`, `readLiteral`, obtains the
   decompressed literal stream and copies it into `ByteArrayOutputStream` with `copyTo(out)` and no
   output ceiling.
4. `app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt:104-105`, `decrypt`, verifies integrity only
   after `readLiteral` has already materialized the expanded plaintext. A valid message can therefore
   reach this point; the issue does not depend on malformed-packet behavior.
5. `app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt:198-199` then passes the complete
   plaintext to `PgpMimeReader`, adding more memory pressure.

Concrete impact: heap exhaustion, process termination, and loss of the current session. Reopening or
retrying the same mail reproduces the failure. The attacker does not gain credentials or mail data.

Remediation: use a bounded stream copy that stops above a documented maximum (for example, the same
per-message plaintext budget used by the mail reader) and return a terminal size error before the
output becomes unbounded. Keep the bound in the decryptor, not only in the HTTP client.
