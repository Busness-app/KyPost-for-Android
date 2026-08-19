# Comment archive - main/pgp (G-Z)

## app/src/main/java/org/kysecurity/mail/pgp/LocalSignerKeysAndroid.kt

### `internal class RoomLocalSignerKeys(context: Context) : LocalSignerKeyLookup {`
```
/**
 * The Room-backed [LocalSignerKeyLookup] — this device's own answer to "whose key is this",
 * assembled from the contact store rather than from the relay's response.
 *
 * Separate file from [SignerBinding] for the same reason [EnrollmentPortsAndroid] is separate from
 * [EnrollmentPorts]: everything the verdict logic itself touches stays free of Android and of Room,
 * so it can be exercised by a JVM test, and the framework lives out here.
 */
```

### `dao.search(needle)`
```
            // The LIKE narrows in SQL; the exact match happens in Kotlin against the DECODED
            // addresses. Matching the raw emailsJson alone would accept `bob@example.com` for a
            // contact whose stored address is `notbob@example.com.evil.tld`, which is a substring
            // of it — fine for autocomplete, which is what that query was built for, and not fine
            // for the input to a trust decision.
```

### `internal fun ContactEntity.hasEmail(address: String): Boolean =`
```
/** Exact, case-insensitive match against a DECODED address. `internal` rather than private so
 *  the two decisions this file actually makes have a JVM test — neither needs Room, and requiring
 *  an emulator to assert "is a substring an address" is how that assertion never gets written. */
```

### `internal fun ContactEntity.toLocalSignerKey(): LocalSignerKey? {`
```
/**
 * A contact row as a signer key, or null when the row carries nothing this device can vouch for.
 *
 * [LocalSignerKey.confirmed] requires all three: a key, a locally-computed fingerprint, and neither
 * alarm outstanding.
 *
 * - `pgpKeyFingerprint` non-null means [PgpFingerprint.compute] accepted the blob — which is what
 *   rejects an appended second key ring and an unbound subkey. A row whose fingerprint is null is
 *   holding a key the local parser refused to vouch for, so it is not offered at all.
 * - `pgpKeyNeedsReverification` is the key alarm: the fingerprint changed under a contact that had
 *   one, or the blob stopped parsing.
 * - `identityNeedsReview` is the identity alarm: same key, different addresses beside it. The QR
 *   ceremony deliberately cannot clear this one, so it must gate the badge the ceremony grants.
 *
 * A row that fails only the alarms still returns a key — with `confirmed = false`. That is not a
 * softening: [signatureStateFor] treats a locally-held key as authoritative about *which* key the
 * sender uses regardless, so returning it is what makes a signature by some other key report
 * KEY_CHANGED instead of falling through to the relay's opinion.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpBootstrapClient.kt

### `sealed class PgpBootstrapResult {`
```
/**
 * Outcome of `GET /api/pgp/bootstrap`.
 *
 * Two cases, not one per status code: the caller's response to *every* failure is identical — hide
 * the PGP controls, because couldn't-check is not "no" — so distinguishing 401 from 503 from a
 * malformed body would be a distinction nothing acts on.
 */
```

### `data class Success(`
```
    /** [protection] is `"server"`, `"client"`, or `""` for an account with no identity. Passed
     *  through as the raw string; [pgpComposeStateOf] decides what it means, and treats anything
     *  unrecognized as "not server". [publicKey] is the account's own armored public key, `""`
     *  when it has no identity — the only device-reachable source for it, and what
     *  [ownFingerprintFromBootstrap] hashes to show the user their own fingerprint. */
```

### `val accountAddress: String = "",`
```
        /** The account's own mail address, and the only device-reachable source for it —
         *  `GET /api/mail/send-as` is session-authenticated, so a paired device cannot ask.
         *
         *  Every client-encrypted delivery's `From` header must equal this exactly or the relay
         *  answers 403, and it is authoritative rather than inferred: the server builds
         *  `suggestedUserIDs[0]` from the same `strings.TrimSpace(payload.Username)` expression that
         *  `handleMailSendPGP` hands to `resolveMailFrom`. Blank when no mail account is configured,
         *  which means no valid `From` can be built at all. */
```

### `@Serializable`
```
/** The three fields this app needs. The endpoint returns considerably more — wrappedPrivateKey,
 *  unlockRequired, signerPublicKeys, payloadEndpoint — all of it for the browser, none of it
 *  usable here, which is why the [Json] instance ignores unknown keys. The response's own
 *  `fingerprint` field is deliberately NOT among them: it is a claim sitting beside `publicKey`
 *  with no cryptographic tie to it, and [PgpFingerprint] exists precisely so the app hashes the
 *  key bytes itself instead of rendering a server-supplied label. */
```

### `class PgpBootstrapClient(`
```
/**
 * Reads the account's PGP key-custody mode. Pairing-authenticated with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret exactly like every other relay call this app makes —
 * there is no mobile login and no session cookie. Kept parallel to [PgpQrClient].
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpComposeState.kt

### `data class PgpComposeState(`
```
/**
 * Which PGP controls the compose screen offers, as a pure function of what
 * `GET /api/pgp/bootstrap` said.
 *
 * Kept out of the Activity for the same reason as [PgpMessageState]: the rule is testable without
 * instrumentation, and the view only picks widgets.
 */
```

### `val handoffToWebmail: Boolean,`
```
    /** Show "Continue in webmail" instead of the toggles: this account's key is held only by the
     *  user, and this device is not enrolled, so neither the server nor this app can encrypt on its
     *  behalf. */
```

### `val clientSide: Boolean = false,`
```
    /** The encryption happens **here**, and the send goes to `/api/mail/send-pgp` rather than
     *  `/api/mail/send`. True only for a client-custody account on an enrolled device.
     *
     *  A single flag rather than leaving the Activity to re-derive the combination: getting it
     *  wrong means posting encrypt/sign flags to the endpoint that answers 409 for precisely this
     *  account type. */
```

### `fun pgpComposeStateOf(`
```
/**
 * [hasIdentity] and [protection] are null when bootstrap could not be reached. Unknown hides
 * everything: guessing "server" offers a toggle that 409s, and guessing "client" sends people to
 * webmail for no reason.
 *
 * An unrecognized non-null [protection] is treated as "not server" — degrade, never guess.
 *
 * [deviceEnrolled] is whether this device still holds the account's private key
 * ([probeEnrollment]). It is a `Boolean` rather than an `EnrollmentStatus` because that enum is
 * `internal` and this function is part of the public surface.
 *
 * [accountAddress] is `suggestedUserIDs[0]` from bootstrap. Blank means no mail account is
 * configured, so no delivery `From` can be built — an enrolled client-custody account still falls
 * back to the handoff rather than offering a Send the relay is certain to refuse.
 */
```

### `protection == PROTECTION_CLIENT && deviceEnrolled && accountAddress.isNotBlank() ->`
```
    // This is the case the earlier "this device never holds the account's private key" contract
    // ruled out; the device enrollment ceremony replaced that contract.
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpDecryptor.kt

### `internal const val MAX_DECRYPTED_PLAINTEXT_BYTES = org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_BYTES`
```
/** See [org.kysecurity.mail.MemoryBudget], which holds this alongside the app's other two heap
 *  ceilings — the three interact and were previously set in three files that could not see each
 *  other. */
```

### `internal sealed class RawSignature {`
```
/**
 * What the cryptography alone can say about a signature: nothing about *who* the sender is.
 *
 * **Three states, not two booleans.** This was `(present, valid, signerKeyId)`, which could not
 * express "signed, by a key we were not given" — that case set `valid = false`, making it
 * indistinguishable from a signature that failed to verify. The two mean opposite things to a user:
 * one is "we could not check this", the other is "we checked, and it is wrong", and INVALID is the
 * strongest accusation this app renders.
 *
 * [signatureStateFor] recovered the distinction by re-matching the key id itself, which held only
 * as long as its filter and [PgpDecryptor.verifyOnePass]'s stayed in agreement — and they did not:
 * `signerKeyIdsOf` drops expired and revoked keys, `verifyOnePass` never did, so a signature by an
 * expired subkey verified there as `valid = true` and was then filtered out here. Right answer,
 * wrong reason, one refactor away from being wrong. Naming the state removes the coupling.
 */
```

### `object Absent : RawSignature()`
```
    /** No signature packet at all. */
```

### `data class Checked(val keyId: Long, val verified: Boolean) : RawSignature()`
```
    /** Signed, a key with this id was found, and [verified] is the result of checking against it. */
```

### `val valid: Boolean get() = (this as? Checked)?.verified == true`
```
    /**
     * True only when a key was actually found AND the signature verified against it.
     *
     * Deliberately false for [NoSuchKey]: a caller asking "is this good" must get "no" for a
     * signature nothing checked. A caller that needs to tell the two apart matches on the type.
     */
```

### `val signerKeyId: Long get() = when (this) {`
```
    /** 0 when there is no signature to attribute. */
```

### `override fun equals(other: Any?) = this === other`
```
        // Kotlin generates identity equals/hashCode for a ByteArray property, and a data class
        // silently promising structural equality it does not provide is a trap. Nothing compares
        // these, so both are explicitly unsupported rather than subtly wrong.
```

### `internal object PgpDecryptor {`
```
/**
 * OpenPGP decryption and signature checking, with **no Android imports**.
 *
 * Uses Bouncy Castle's lightweight `Bc*` operators rather than the `Jce*` ones. Android ships a
 * stripped-down "BC" JCE provider that collides with the full one, so the `Jce*` path behaves
 * differently on a device than in a JVM test. The `Bc*` path uses no JCE provider at all, so the
 * same code runs identically in both — which is what makes [PgpDecryptorTest] evidence rather than
 * decoration under the project-wide `isReturnDefaultValues = true`.
 *
 * Every failure is a [DecryptResult.Failed], never a throw: the caller renders an exit-table row.
 */
```

### `signerPublicKeys: List<String>,`
```
        /** The public keys the address book binds to the displayed sender, from [SignerKey]. A
         *  one-pass signature cannot be completed without one, and the key travelling inside the
         *  signed message is deliberately never used: a message that vouches for itself proves
         *  only that whoever wrote it owned a key. Empty means "present but unverifiable". */
```

### `if (!encrypted.isIntegrityProtected || !encrypted.verify()) {`
```
        // Integrity protection is not optional. An unprotected message is malleable, and
        // accepting one would let a tampered ciphertext render as an ordinary message. The `||`
        // short-circuits before `verify()`, which throws outright on a packet that was never
        // integrity protected in the first place — a legacy Symmetrically Encrypted Data (tag 9)
        // packet rather than the Sym. Encrypted Integrity Protected Data (tag 18) one. Covered by
        // failsClosedOnAnUnprotectedMessage; ARMORED_UNPROTECTED_MESSAGE is the reachable fixture
        // for that branch, made with `gpg --rfc2440 --disable-mdc`.
```

### `fun verifyDetached(`
```
    /**
     * Verifies an RFC 3156 detached signature over an already-readable body.
     *
     * **The two catches below are scoped separately, and conflating them was a downgrade.** A
     * failure to *parse* means no signature was readable at all, which is `present = false` — the
     * same thing `decrypt()` reports for a message that never parsed as OpenPGP. A failure inside
     * `init`/`update`/`verify` means a signature was found and is broken, which is
     * `present = true, valid = false`.
     *
     * One `runCatching` around the whole body mapped both to `present = false`, so a signature
     * truncated or corrupted in transit rendered as "this message is unsigned" — a state users see
     * on ordinary mail every day — instead of the alarm a mangled signature has to raise.
     */
```

### `private fun readLiteral(`
```
    /**
     * Walks the decrypted stream to its literal data, checking any one-pass signature on the way.
     */
```

### `if (++depth > MAX_COMPRESSION_DEPTH) return null`
```
                    // Bounded. `readAllWithLimit` caps the *literal* data; nothing capped how many
                    // compressed layers were unwrapped on the way to it, and each one allocates a
                    // fresh object factory over a fresh inflater. A sender who nests thousands of
                    // compressed packets exhausts the heap before a single literal byte is read —
                    // and the message stays in the mailbox, so it re-fires on every open.
```

### `internal fun readAllWithLimit(input: InputStream, limit: Int): ByteArray? {`
```
    /**
     * Bounds the stream after OpenPGP decompression, and returns null once [limit] is exceeded.
     *
     * Accumulates fixed chunks and joins once, rather than writing into a [ByteArrayOutputStream]
     * and calling `toByteArray()`. BAOS grows by doubling, so a message at the ceiling held a
     * full-size buffer plus the half-size one it had just outgrown, then allocated a third for the
     * copy — roughly 2.5x peak and ~2x the memcpy, for an input a hostile sender fully controls.
     *
     * **The peak here is 2x [limit], not 1x, and that is irreducible.** Materialising an
     * exact-length [ByteArray] from a stream whose length is unknown until it ends requires the
     * accumulated bytes and the joined result to exist at the same instant, whatever the
     * accumulation strategy. [org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_PEAK_BYTES] states
     * that multiplier rather than leaving the budget to imply 1x; the two must move together.
     *
     * The list is drained as it is joined, so the peak is paid at the first copy and falls away
     * across the rest of it instead of being held until the loop ends.
     *
     * A fresh buffer per `read()` is deliberate and is NOT a hoisting opportunity: a full buffer is
     * handed to [chunks] by reference, so reusing one would mean copying every chunk instead — the
     * same allocation count plus a full extra memcpy of the message. Only the final short read is
     * copied, and only to trim it.
     */
```

### `private fun verifyOnePass(`
```
    /**
     * Completes a one-pass signature against the literal bytes just read.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpEncryptor.kt

### `internal object PgpEncryptor {`
```
/**
 * OpenPGP encryption and signing, with **no Android imports** — the outbound mirror of
 * [PgpDecryptor].
 *
 * Uses Bouncy Castle's lightweight `Bc*` operators rather than the `Jce*` ones, for the reason
 * [PgpDecryptor] gives: Android ships a stripped-down "BC" JCE provider that collides with the full
 * one, so the `Jce*` path behaves differently on a device than in a JVM test. The `Bc*` path uses no
 * JCE provider at all, which is what makes [PgpEncryptorTest] evidence rather than decoration under
 * the project-wide `isReturnDefaultValues = true`.
 *
 * Every failure is an [EncryptResult.Failed], never a throw, matching [PgpDecryptor]'s contract.
 */
```

### `if (recipientPublicKeys.isEmpty()) {`
```
        // Explicit rather than emergent. Bouncy Castle already throws when the generator is opened
        // with no recipient method, which runCatching would turn into a Failed — but a documented
        // contract resting on a library's incidental throw is one upgrade away from becoming a
        // message encrypted to nobody and reported as sent.
```

### `val encryptionKeys = recipientPublicKeys.map { armored ->`
```
        // A recipient whose key cannot be parsed or carries no usable encryption key is a hard
        // failure, never a skip: skipping means that person silently cannot read their own mail
        // while the sender is told the message went out.
```

### `signer?.generateOnePassVersion(false)?.encode(compressedOut)`
```
                // Packet order is the whole contract of a one-pass signature, and it is what
                // PgpDecryptor.readLiteral walks: the one-pass header, then the literal data, then
                // the signature. Any other order still decrypts, so only a verified signature
                // proves this is right.
```

### `fun ownPublicKey(armoredPrivateKey: CharArray): String? = runCatching {`
```
    /**
     * The armored public half of the enrolled private key, for encrypting the Sent copy.
     *
     * Derived from the unlocked private key and never fetched from the server. A hostile or
     * compromised server that could supply "your" public key would otherwise get every Sent copy
     * encrypted to a key it holds, with nothing on screen looking any different.
     *
     * Carries the whole ring, not just the master key: on the ed25519/cv25519 pairs this product
     * generates only the subkey encrypts, so a master-only export would be unusable as a recipient.
     */
```

### `private fun encryptionKeyOf(armoredPublicKey: String): PGPPublicKey? = runCatching {`
```
    /**
     * The key a message should actually be encrypted to.
     *
     * For the ed25519/cv25519 pairs this product generates the master key signs and only the subkey
     * encrypts, so taking the master would produce a message the recipient cannot open.
     *
     * Recipient key material comes from the relay, which client-side custody exists precisely not to
     * trust, so the blob is validated locally before any of it is used. [PgpFingerprint.compute] is
     * the same validator the QR and contact-sync paths already apply, and it rejects the two shapes
     * that leave the primary fingerprint — the string a user compares out of band — describing only
     * part of what gets used: an appended second key ring, and a subkey bound by a foreign signature
     * or by none at all. Revocation is then filtered here because [PGPPublicKey.isEncryptionKey]
     * ignores it, so a subkey its own owner has retired was otherwise still a valid selection.
     *
     * Returning null is a hard failure at the call site, never a skipped recipient — see [encrypt].
     */
```

### `.maxByOrNull { it.creationTime.time }`
```
            // Newest, not "last in the serialisation". `lastOrNull()` happened to be right for the
            // ed25519/cv25519 pairs this product generates, where exactly one subkey encrypts — and
            // silently picked whichever subkey a third-party key happened to serialise last when
            // there were two, which is how a recipient gets a message under a subkey they have
            // rotated away from.
```

### `private fun PGPPublicKey.hasExpired(nowMillis: Long = System.currentTimeMillis()): Boolean {`
```
    /**
     * Whether this key's own stated validity period has run out.
     *
     * Checked alongside revocation because [PGPPublicKey.isEncryptionKey] ignores both. Without it,
     * a recipient whose key expired last year still got a message encrypted to it and the sender
     * was told it went out — the failure the "a recipient key is unusable" hard stop in [encrypt]
     * exists to surface, arriving as silence instead.
     *
     * `validSeconds == 0` means "no expiry" in OpenPGP, which is the common case and is not an
     * expiry of zero seconds.
     */
```

### `private fun signatureGeneratorFor(armoredPrivateKey: CharArray): PGPSignatureGenerator? = runCatching {`
```
    /**
     * A one-pass signature generator initialised from the enrolled private key.
     *
     * The empty passphrase matches [PgpDecryptor]: the armored key came out of the device envelope
     * already unwrapped, so a key that still needs one is not a key this device can use.
     */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpFingerprint.kt

### `object PgpFingerprint {`
```
/**
 * Computes an OpenPGP key's fingerprint from the key's own bytes, rather than trusting whatever
 * fingerprint string a server response claims alongside it. A compromised/malicious server (or a
 * MITM on an http fallback) could otherwise send an armored key paired with an unrelated
 * fingerprint string, and the app would have no way to notice the two don't match — the user's
 * out-of-band "does this fingerprint match?" check would be verifying a label with no
 * cryptographic relationship to what actually gets saved. Parsing the key locally and hashing what
 * it actually contains closes that gap.
 */
```

### `fun compute(armoredPublicKey: String): String? = runCatching {`
```
    /** Returns the primary key's fingerprint as space-grouped uppercase hex (comparable to what
     *  `gpg --fingerprint` or any other PGP client shows), or null if [armoredPublicKey] isn't a
     *  parseable OpenPGP public key. Callers must treat null as "reject this key" — never fall back
     *  to displaying a server-supplied fingerprint string instead. */
```

### `if (factory.nextObject() != null) return@runCatching null`
```
        // Verify the whole artifact, not just its first object. Callers persist the ENTIRE armored
        // blob, so anything this function does not look at is key material the user's out-of-band
        // fingerprint check never covered:
        //
        //  - BouncyCastle's PGPPublicKeyRing stream constructor stops its subkey loop at a second
        //    PUBLIC_KEY packet, so an appended second key ring becomes an object nextObject() never
        //    returns — invisible here, still saved and uploaded.
        //  - That same constructor stores subkeys without ever verifying their binding signatures,
        //    so a subkey bound by a foreign signature, or by none at all, survives intact.
        //
        // Both are rejected rather than tolerated: a blob whose fingerprint does not describe all
        // of it cannot be meaningfully confirmed by a human comparing one string.
```

### `internal fun hasValidBindingSignature(`
```
/**
 * Whether [subkey] carries a subkey-binding signature that verifies under [primary].
 *
 * File-level and `internal` rather than private to [PgpFingerprint], because two call sites need
 * it and only one had it. [org.kysecurity.mail.pgp.signerKeyIdsOf] was accepting every subkey in a
 * ring without asking this question at all — see its KDoc for what that let through.
 *
 * The **Bc** verifier, not the Jca one, matching [PgpDecryptor]'s identical `signature.init`.
 *
 * The Jca operator converts the primary key to a JCE `PublicKey` first, which needs an EdDSA
 * `KeyFactory` from the platform JCA. Android ships no such provider — its "BC" is stripped and
 * the only Ed25519 signer is `AndroidKeyStoreBCWorkaround`, for Keystore-resident keys — so
 * every ed25519 key threw "exception constructing public key" here, the subkey read as unbound,
 * and the whole key was rejected as unparseable. That surfaced as "couldn't check whether your
 * account uses encrypted mail" on the Security page, with no way to enroll. The JVM tests
 * passed throughout: desktop JDKs *do* have EdDSA, and every fixture was a bare primary key
 * with no subkey, so this function never ran. Bc uses BouncyCastle's own lightweight math and
 * asks the platform for nothing.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpIdentityStatus.kt

### `internal fun pgpIdentityFromMintResult(result: PgpQrTokenResult): Boolean? = when (result) {`
```
/** Maps a [PgpQrTokenResult] (from [PgpQrClient.mintToken]) to "does this account have a PGP
 *  identity" — `true`/`false` are definitive answers, `null` means the question couldn't be
 *  answered (not paired, network error, server error) and callers should leave whatever they were
 *  already showing alone rather than treating "couldn't check" as "no". Pulled out as its own pure
 *  function so it's unit-testable without a Context/PushRuntime dependency. */
```

### `suspend fun hasPgpIdentity(`
```
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
```

### `internal fun ownFingerprintFromBootstrap(result: PgpBootstrapResult): String? = when (result) {`
```
/**
 * The account's own PGP fingerprint, computed locally from the public key `GET /api/pgp/bootstrap`
 * returned, or null when the account has no identity, the key doesn't parse, or the call failed.
 *
 * Hashing those bytes rather than reading the response's `fingerprint` field is the same rule
 * [PgpKeyActivity.showFetchedKey] follows for the other party's key: a fingerprint the user is
 * about to read aloud must describe the key material actually in hand.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpKeyActivity.kt

### `class PgpKeyActivity : LockedActivity() {`
```
/**
 * "PGP Key Signing": a single screen that shows the user's own PGP QR code (minted via
 * [PgpQrClient.mintToken], re-minted every time the screen resumes so it's never stale) for
 * someone else to scan, plus a "Scan QR Code" button that scans someone else's code directly —
 * no intermediate navigation screen.
 *
 * On a successful scan, fetches the key via [PgpQrClient.fetchKey] (unauthenticated — the token
 * is the credential), shows the fingerprint for out-of-band confirmation, then either creates a new
 * contact from the included card (if present) or lets the user pick an existing contact (via
 * [ContactsListActivity] in pick mode) to save the key onto.
 *
 * Saving does NOT go through a per-contact REST endpoint — this app never calls those. It follows
 * [org.kysecurity.mail.contacts.ContactEditActivity.save]'s exact pattern instead: `queueUpdate` on the
 * existing [org.kysecurity.mail.contacts.ContactDto] with `pgpKey` set, then `syncNowAsync()`.
 */
```

### `private val client by lazy { PgpQrClient(callFactory = pinnedPairingCallFactory(this)) }`
```
    // lazy: pinnedPairingCallFactory(this) needs a valid Context, which isn't available yet at
    // property-initializer time (before attachBaseContext) — deferring to first use (both call
    // sites are well after onCreate) avoids a NullPointerException here. See finding C2 of the
    // 2026-07-22 security-hardening spec's final-review fix round.
```

### `val ownUrl = ownQrUrl(serverUrl, token.token)`
```
        // Build the URL locally against the paired origin rather than encoding the server-supplied
        // `token.url`. That field was rendered verbatim, so a tampered token response could point
        // the counterparty's unauthenticated fetch at any host — outside the TLS pin — and have
        // them save an attacker's key as ours. The token is the only part we need from the server.
```

### `private fun renderOwnFingerprint(serverUrl: String, deviceId: String, deviceSecret: String) {`
```
    /**
     * Shows the user their own fingerprint beside the QR, so that when the other device asks them
     * to "confirm this fingerprint matches", they have something on screen to compare it to.
     */
```

### `val localFingerprint = PgpFingerprint.compute(key.publicKey)`
```
        // The server's `fingerprint` field is never used for the confirmation prompt below — it's
        // just another claim in the same response as `publicKey`, with no cryptographic tie to it.
        // Computing the fingerprint locally from the key bytes themselves is what makes "confirm
        // this fingerprint matches" an actual verification instead of a rubber stamp.
```

### `val addresses = scannedAddresses(key)`
```
        // Verifying the fingerprint proves which KEY this is; it says nothing about which
        // addresses the key gets bound to. Those travel beside the key in `contactCard`, are
        // chosen by whoever served the QR, and are what the server's resolver later matches on —
        // so mail to any of them would be encrypted to this key. Show them before accepting.
```

### `private suspend fun confirmBinding(name: String, addresses: List<String>): Boolean =`
```
    /**
     * Last gate before a key is bound to an existing contact: shows the addresses that contact
     * currently holds and waits for the user to accept them.
     *
     * The scan confirmation earlier in this flow lists the addresses from the *scanned card*, which
     * on this branch are not the addresses the key ends up bound to — the DTO is built from the Room
     * row. Those two can differ, and a third-party `WRITE_CONTACTS` write is exactly how.
     */
```

### `val boundAddresses = entity.toDto().emails.map { it.value }.filter { it.isNotBlank() }`
```
            // The addresses the key is about to be bound to are the ones already on THIS contact —
            // not the ones on the scanned card, which is what the confirmation screen showed. Any
            // app holding WRITE_CONTACTS can have rewritten them, so they are restated here, at the
            // point of commitment, before the binding is made.
```

### `graph.repository.queueUpdate(dto, identityChanged = false, verifiedInPerson = true)`
```
            // The user just compared this fingerprint out-of-band against the other person's
            // device, so this is a verified rotation, not a suspicious one. Without the flag the
            // mapper raised "Key changed" on the one path where reverification is provably
            // unnecessary, which trains users to dismiss the app's only TOFU alarm.
            // identityChanged = false: this save changes only the key, never the addresses — the
            // DTO is the existing row with pgpKey swapped. It is deliberately not a claim that the
            // addresses are trustworthy; toEntity no longer lets verifiedInPerson clear an
            // identity-rebind alarm, so one raised earlier survives this ceremony.
```

### `internal fun ownQrUrl(serverUrl: String, token: String): String? {`
```
        /** The inverse of [parsePgpQrKeyUrl]: builds the URL our own QR encodes, from the paired
         *  server URL plus the minted token. Deliberately does not use the server's `url` field —
         *  see [renderQr]. Returns null if [serverUrl] or [token] can't form a valid URL. */
```

### `internal fun contactDtoFromCard(card: PgpQrContactCardDto, fallbackName: String, pgpKey: String): ContactDto =`
```
        /** Maps a scanned [PgpQrContactCardDto] to a creatable [ContactDto], for the "Create New
         *  Contact" path in [showSaveChoiceDialog]. [fallbackName] (the scan's top-level `name`)
         *  fills in `fn` when the card itself carries no name — `ContactDto.fn` must be non-blank
         *  per Mobile_Contact_Sync.md, and a card's `fn` is `omitempty` server-side so it can be
         *  legitimately absent. */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpMessageState.kt

### `enum class PgpMessageState {`
```
/**
 * What this app can actually do with a message's OpenPGP content.
 *
 * Kept as a pure function of the three relay fields so the decision is unit-testable without
 * instrumentation — the Activity only picks views, it does not re-derive the rule.
 */
```

### `CLIENT_PROTECTED,`
```
    /**
     * Encrypted, and the server deliberately did not decrypt it because the account's key is
     * end-to-end protected. The inbox row and detail Intent still carry no body — that much is
     * still true — but this app can hold the private key now: [EnrollmentSession] caches it for
     * one unlock session once the user enrols this device, and [EncryptedMessageReader] decrypts
     * locally from it. Webmail is a fallback for a device that has not enrolled, not the only
     * route.
     */
```

### `DECRYPTED_BY_SERVER,`
```
    /**
     * Encrypted, and the server decrypted it for us. Worth surfacing rather than rendering
     * silently: the user should be able to tell that the server read their mail.
     */
```

### `BODY_UNAVAILABLE,`
```
    /**
     * Encrypted, but we do not have this message cached and cannot tell which of the states above
     * applies. Distinct from [CLIENT_PROTECTED] on purpose: an absent body is not evidence of
     * client-side protection, and conflating the two made the app assert the *stronger* privacy
     * property exactly when the weaker one held — concealing the fact that the server had read the
     * mail. Under Hostile Location Protection this is the normal state of every cold process.
     */
```

### `fun pgpMessageStateOf(`
```
/**
 * The ordering matters. A non-empty [pgpDecryptError] is checked before the body, because the
 * server populates the error and leaves the body empty — reading it as CLIENT_PROTECTED would
 * tell the user to go to webmail for a message that will fail there too, for a reason we were
 * already told.
 */
```

### `fun rendersNothing(state: PgpMessageState, body: String?, preview: String): Boolean =`
```
/**
 * Whether the screen would otherwise render **nothing at all**: no body, no preview text, and no
 * PGP notice explaining the absence.
 *
 * The one combination the state machine above cannot speak for: [PgpMessageState.NONE] means "render
 * normally", which is correct right up to the point where there is nothing to render.
 *
 * Reachable, and not rare. `pgpEncrypted` is `omitempty` server-side and defaults to `false` here,
 * so **an encrypted message the server has not warmed yet is indistinguishable on the wire from an
 * unencrypted one** — flag clear, no body, lands in [NONE].
 *
 * Nothing here guesses which case it is. The client cannot tell an unwarmed encrypted message from a
 * genuinely empty one, and inventing a lock glyph for the first would assert the stronger privacy
 * property on evidence that does not support it — the mistake [PgpMessageState.BODY_UNAVAILABLE]
 * exists to prevent. It only says that *something* should be on screen.
 */
```

### `enum class PgpSignatureState {`
```
/**
 * Whether the relay could tie this message's OpenPGP signature to the sender.
 *
 * Kept separate from [PgpMessageState], which answers "can this content be read here?" — a message
 * can be perfectly readable and still be signed by someone other than who it claims to be from, and
 * that is precisely the case worth surfacing.
 *
 * The relay computes three of these states — [PgpSignatureState.VERIFIED_SEEN_BEFORE],
 * [PgpSignatureState.NONE] and [PgpSignatureState.INVALID] — and returns them as
 * `pgpSigned`/`pgpVerified`/`pgpSignerFingerprint` per message; see [pgpSignatureStateOf]. The
 * other three ([PgpSignatureState.VERIFIED_CONFIRMED], [PgpSignatureState.SIGNER_UNKNOWN],
 * [PgpSignatureState.KEY_CHANGED]) come only from a local decrypt against a locally-held key, via
 * [signatureStateFor] — see that KDoc below.
 */
```

### `VERIFIED_SEEN_BEFORE,`
```
    /**
     * Signed by a key bound to the sender that still matches its TOFU pin, but which nobody ever
     * confirmed. This claims **continuity**, not identity: the same key as last time.
     *
     * Distinct from [VERIFIED_CONFIRMED] because most keys arrive by Autocrypt harvest, so one flat
     * "verified" badge would assert the stronger property on the weaker evidence for nearly every
     * message — and a badge that over-claims on the common case is one users learn to ignore.
     */
```

### `SIGNER_UNKNOWN,`
```
    /**
     * Signed, but not by any key we hold for this sender. This is not an accusation: the same
     * verdict results from an ordinary correspondent who is not in the address book yet, from a
     * sender whose key rotated before we harvested the new one, and from someone else signing with
     * their own key under a forged `From` header naming this sender. Those three are locally
     * indistinguishable, so this state deliberately claims no more than what is actually known.
     */
```

### `fun pgpSignatureStateOf(`
```
/**
 * The relay's verdict, for accounts whose key the **server** holds.
 *
 * Two booleans cannot express six states, and they cannot distinguish a fingerprint-confirmed key
 * from an Autocrypt-harvested one, so `pgpVerified` maps to the weaker of the two positive claims.
 * [PgpSignatureState.VERIFIED_CONFIRMED] and [PgpSignatureState.KEY_CHANGED] are reachable only
 * through [signatureStateFor], from a local decrypt against a locally-held key.
 *
 * `pgpSignerFingerprint` is what keeps this from accusing everyone. The relay does not verify
 * signed-but-unencrypted mail at all — it cannot, because a detached signature covers the signed
 * MIME part's transmitted bytes and every server-side path holds a decoded copy — so `pgpVerified`
 * is permanently false for that entire population. Reading `signed && !verified` as
 * [PgpSignatureState.INVALID] therefore fired the accusation on **every correctly signed message**,
 * which is exactly the alarm fatigue that makes the marker worthless when a real key substitution
 * arrives. An empty fingerprint means nothing was checked against anything; a non-empty one means a
 * key produced the signature and it was not the sender's. Only the second is an accusation.
 */
```

### `fun pgpRowMarker(`
```
/**
 * Marker for an inbox row, or null for no marker.
 *
 * Four states are marked, not two: [PgpMessageState.CLIENT_PROTECTED] and
 * [PgpMessageState.DECRYPT_FAILED] for readability, via [pgpReadabilityMarker] — plus, regardless of
 * readability, [PgpSignatureState.INVALID] and [PgpSignatureState.KEY_CHANGED], which mark even a
 * row that opens and reads normally (see the `signature` parameter below).
 * [PgpMessageState.DECRYPTED_BY_SERVER] is the one deliberately unmarked readability state: the row
 * opens and reads normally, so a marker there would be a symbol on most rows in a server-mode
 * mailbox carrying no information the user can act on — and the detail view already discloses that
 * the server decrypted it.
 */
```

### `signature: PgpSignatureState = PgpSignatureState.NONE,`
```
    /** A failed signature or a changed key outranks every readability marker: the row is
     *  readable, and that is exactly what makes an unflagged impersonation dangerous.
     *  SIGNER_UNKNOWN deliberately does not mark — see [PgpSignatureState.SIGNER_UNKNOWN]. */
```

### `PgpSignatureState.INVALID, PgpSignatureState.KEY_CHANGED -> "⚠"`
```
    // KEY_CHANGED is unreachable here today: EmailAdapter, this function's only caller, derives
    // `signature` from pgpSignatureStateOf, which cannot produce KEY_CHANGED (see its own KDoc —
    // that state comes only from a local decrypt via signatureStateFor). Kept so that if a future
    // row-level local verdict starts producing it, this marker does not silently regress.
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpMimeReader.kt

### `internal data class DecryptedBody(`
```
/**
 * The readable parts of a decrypted PGP/MIME message.
 *
 * Both [html] and [plain] are kept rather than collapsing to one: the caller decides what to put in
 * the WebView, and a message with only a plain part must not render as an empty page.
 */
```

### `internal object PgpMimeReader {`
```
/**
 * Parses decrypted PGP/MIME bytes with `angus.mail`, with **no Android imports**.
 *
 * Note this is `angus.mail`'s first use in this app — it has been a declared dependency, imported by
 * nothing, so "already on the classpath" was never the same as "known to work here".
 *
 * Returns null rather than throwing on anything unparseable. The caller renders an exit-table row;
 * putting unparsed bytes into a WebView is not a degradation this accepts.
 */
```

### `if (s != null && (html == null || html!!.isBlank())) html = s`
```
                        // A blank part is real content — a multipart whose only text part is empty
                        // must yield "" and not null. But it must not lock the slot: a later
                        // sibling with actual content has to win, or it is silently dropped and
                        // the message renders blank with no error.
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpMimeWriter.kt

### `/** One outgoing attachment, already base64-encoded — the form `OutgoingAttachment` already holds. */`
```
/**
 * Outbound PGP/MIME construction, with **no Android imports** — the writing counterpart to
 * [PgpMimeReader].
 *
 * Hand-assembled strings rather than `jakarta.mail`'s `MimeMessage`, deliberately. The requirement
 * is not "emit valid MIME", it is "emit the exact byte shape the relay's own validator accepts and
 * the browser client already produces". A string builder is directly reviewable against that
 * validator; a `MimeMessage` is not, and `saveChanges()` would synthesize and rewrite headers
 * underneath us. `PgpMimeReader` stays `angus.mail`'s only use — which is what lets it serve as an
 * independent oracle for these tests instead of validating the writer with the writer's own library.
 */
```

### `internal data class OutgoingEnvelope(`
```
/**
 * The outer, cleartext envelope of a delivery. There is deliberately **no `bcc` field**: a `Bcc`
 * header is refused outright by the relay, and each BCC recipient gets their own delivery so they
 * never appear in one another's headers. Making it unrepresentable is stronger than remembering not
 * to write it.
 */
```

### `internal fun wrapAsPgpMime(`
```
/**
 * Wraps an armored PGP message as a complete RFC 5322 message with an RFC 3156
 * `multipart/encrypted` body.
 *
 * Emits the **full** envelope, not just the Content-Type: `/api/mail/send-pgp` relays these bytes
 * verbatim, so anything omitted here is simply absent from the delivered mail.
 *
 * The header set is fixed and closed — there is no caller-supplied header path at all, which is what
 * structurally guarantees the relay's forbidden headers can never appear.
 */
```

### `internal fun buildProtectedContent(`
```
/**
 * Wraps the real content in a protected-headers part carrying the true Subject.
 *
 * The outer envelope's Subject is a fixed placeholder, so this is the only place the real one
 * travels — inside the ciphertext. [PgpMimeReader] lifts it back out as
 * [DecryptedBody.protectedSubject].
 */
```

### `if (clean.isNotEmpty()) {`
```
    // The memoryhole convention. KyPost's own reader takes the subject off the top-level header
    // above, but Thunderbird, Mutt and K-9 look for it here — without this part they show the outer
    // placeholder instead of the real subject.
```

### `internal fun rfc5322Date(at: OffsetDateTime): String =`
```
/**
 * The `Date` header, which the relay requires and does not synthesize.
 *
 * `RFC_1123_DATE_TIME` needs no `withLocale`: RFC 1123 mandates fixed English day and month
 * abbreviations, so the constant hardcodes them and emits ASCII even when its own `getLocale()`
 * reports `tr_TR` (verified, not assumed). **Do not replace it with
 * `ofPattern("EEE, dd MMM yyyy HH:mm:ss Z")`** — that renders through the default locale and yields
 * "Sal, 11 Ağu 2026" on a Turkish device, i.e. non-ASCII in an RFC 5322 header.
 * `dateIsAsciiUnderANonEnglishDefaultLocale` is the guard against exactly that edit.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpPayloadClient.kt

### `internal sealed class PgpPayloadResult {`
```
/**
 * The outcome of asking the relay for one message's OpenPGP payload.
 *
 * The three specific status codes are distinct cases rather than one [Failed], because each gets a
 * different exit-table row and a different sentence to the user. Collapsing them would tell someone
 * whose message is simply too large that the server could not be reached.
 */
```

### `internal class PgpPayloadClient(`
```
/**
 * Reads one message's OpenPGP ciphertext via `GET /api/mail/pgp-payload`. Pairing-authenticated with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret exactly like every other relay call this app makes.
 *
 * Kept parallel to [PgpBootstrapClient] and [RecipientKeyClient]: same injectable [Call.Factory] so
 * tests run without a real network call, same device-header auth.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpQrClient.kt

### `data class NoIdentity(val message: String) : PgpQrTokenResult()`
```
    /** 400: caller has no PGP identity configured yet. There is no in-app fix — generating a PGP
     *  identity is a web-session-only action on the backend, so callers should point the user to
     *  the web app rather than any in-app settings screen. */
```

### `class PgpQrClient(`
```
/**
 * Talks to the backend's PGP QR key-exchange endpoints. `mintToken` is pairing-authenticated
 * exactly like every other endpoint this app calls (X-Kypost-Device-Id/X-Kypost-Device-Secret
 * headers, never a session cookie — this app has no session-cookie concept). `fetchKey` is
 * unauthenticated; the token itself is the credential. Kept parallel to
 * [org.kysecurity.mail.contacts.ContactSyncClient] — same okhttp/serialization stack and
 * status-code-to-result mapping shape.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/PgpQrModels.kt

### `@Serializable`
```
/** The shareable subset of the token owner's self-contact (server's `contacts.Contact` with
 *  `isSelf == true`), included in [PgpQrKeyDto] when they have one set. Field names and types
 *  mirror the server's `pgpQRContactCard` struct exactly (`backend/internal/api/pgp_qr_handlers.go`
 *  in kypost-server); it reuses this app's existing [ContactFieldDto]-family types rather than
 *  duplicating them, since [org.kysecurity.mail.contacts.ContactDto] already models the identical JSON
 *  shapes for the app's own contact sync. */
```

## app/src/main/java/org/kysecurity/mail/pgp/RecipientFields.kt

### `internal fun splitRecipientFields(to: String, cc: String, bcc: String): RecipientFields {`
```
/**
 * Splits the compose screen's comma-joined recipient fields, keeping each field distinct.
 *
 * **Not [org.kysecurity.mail.splitAddresses].** That one flattens all three fields into a single deduped
 * list, which is correct for the preflight — the question there is "which addresses need a key", and
 * asking twice about one person is only noise. Reusing it here would collapse a BCC recipient into
 * the To bucket, putting someone the sender marked blind into a header every other recipient reads.
 *
 * Overlap is resolved by precedence rather than kept: an address already in To is dropped from CC
 * and BCC, and one already in CC is dropped from BCC. Keeping it would build that person a second,
 * redundant delivery *and* leave the sender believing the extra copy was blind when the To header
 * already names them. First spelling wins, since that is the one the user typed and will see named
 * back to them.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/RecipientKeyClient.kt

### `sealed class RecipientKeyResult {`
```
/**
 * Outcome of the recipient-key preflight.
 *
 * [Failed] is deliberately distinct from `Success(emptyList())`: a failed lookup must never read
 * as "everyone has a key", which would let the compose screen imply an encrypted send it knows
 * nothing about.
 */
```

### `data class Success(val keyless: List<String>) : RecipientKeyResult()`
```
    /** [keyless] holds the addresses with no usable key **in the user's contacts**. This is a
     *  lower bound, not a prediction: the send path additionally runs WKD and keyserver discovery,
     *  so an address listed here may still be encrypted to successfully. Use it to warn, never to
     *  promise — the server's 409 is the real gate. */
```

### `@Serializable`
```
/** `revoked`, `expired` and `tier` are parsed but unused: the server already folds revoked and
 *  expired into [hasKey], and `tier` drives the web UI's per-recipient badges. They are declared
 *  only to document the shape — do not re-derive keyless from them. */
```

### `class RecipientKeyClient(`
```
/**
 * Asks which recipients have a usable PGP key, via `POST /api/pgp/recipients/check`.
 *
 * **Not a replacement for [RecipientResolveClient], and not replaced by it.** This endpoint is the
 * cheap, contacts-only, no-network preflight behind the inline "no key on file" warning, and it
 * serves *both* send paths. `/api/pgp/recipients/resolve` hands back actual key material and runs
 * the full WKD and keyserver ladder; it is only meaningful when this device does the encrypting.
 *
 * An earlier revision of this comment said `/resolve` "refuses with 409 for any account that is not
 * client-protected — which is every account that can send encrypted from this app". The first half
 * is still true; the second stopped being true when the device enrollment ceremony gave this app the
 * account's private key, so a client-custody account can now encrypt here and `/resolve` is exactly
 * the right call for it.
 *
 * Kept parallel to [PgpQrClient]: same device-header auth, same injectable [Call.Factory].
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/RecipientResolveClient.kt

### `data class ResolvedRecipientKey(`
```
/**
 * One recipient's resolved key.
 *
 * [usable] is the server's own verdict, already folding in revocation and expiry — do not re-derive
 * it from [tier]. [tier] explains *where* the key came from and is what distinguishes a broken pin
 * from a missing key: `key_changed` means discovery found a key whose fingerprint does not match the
 * one pinned to that contact, which is what a key rotation looks like and also what an interception
 * attempt looks like.
 */
```

### `class RecipientResolveClient(`
```
/**
 * Fetches recipients' actual public keys via `POST /api/pgp/recipients/resolve`, so this device can
 * encrypt locally for a client-custody account.
 *
 * The sibling of [RecipientKeyClient], and **not** a replacement for it. `/check` is the cheap,
 * contacts-only preflight that drives the inline "no key on file" warning on both send paths;
 * `/resolve` runs the full discovery ladder — contacts, then WKD, then keyserver — and hands back
 * key material, which is only meaningful when this device is the one doing the encrypting.
 *
 * **Body format differs from `/check`.** Here 200, 409 and 413 are all JSON, while 400 and 500 are
 * plain text. Decoding a plain-text body would report "malformed response" for a real server error.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/Sec1Point.kt

### `internal fun sec1UncompressedPoint(x: BigInteger, y: BigInteger): ByteArray =`
```
/**
 * Encodes a P-256 public key as the uncompressed SEC1 point `0x04 ‖ X ‖ Y`, each coordinate
 * left-padded to exactly 32 bytes. 65 bytes.
 *
 * Pure and Android-free so both padding branches can be unit-tested. That matters more than it
 * looks: this is a bit-for-bit contract with a Go server and a TypeScript browser client, and a
 * disagreement does not fail loudly — it fails as "the codes never match" on every honest
 * enrollment, which the browser reports to the user as *"the key this server gave the browser is
 * not the key on that device"*. An encoding bug arrives dressed as an active attack.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/SignerBinding.kt

### `internal data class SignerKey(`
```
/**
 * One address-bound contact key as the server ships it.
 *
 * [addresses] is the binding the **server's** address book computed. The client must not re-derive
 * it from the key's own User IDs: one key can self-assert two User IDs, so a binding taken from the
 * key material is forgeable, and re-deriving it with a second parser is how a client can end up
 * vouching for a key the server's own binding rejects.
 */
```

### `val verified: Boolean,`
```
    /**
     * The relay's claim that the user confirmed this key.
     *
     * **Read by nothing that decides a verdict**, and that is deliberate — see [signatureStateFor].
     * It is the server asserting the strongest trust state in the app about a key the same response
     * supplied. Kept on the type because the wire format still carries it and dropping the field
     * would silently discard it on a round trip; do not reintroduce a read of it.
     */
```

### `internal fun signerKeyIdsOf(armoredPublicKey: String, now: Date = Date()): Set<Long> = runCatching {`
```
/**
 * Every **currently usable** key id in [armoredPublicKey]: its primary key plus every subkey,
 * regardless of that subkey's usage flags — an encryption-only subkey's id is returned exactly like
 * a signing subkey's.
 *
 * This is the only place revocation and expiry are enforced. [signatureStateFor] answers
 * SIGNER_UNKNOWN for a signature whose key id is not in this set, so a key dropped here can never
 * render as VERIFIED however cleanly its signature verifies — which is what makes the omission
 * below matter.
 *
 * **A ring is dropped whole when its primary key is revoked or expired.** Per-key filtering alone
 * checked each subkey's own revocation signature and never the primary's, so revoking a compromised
 * *primary* — which is what a user does when their key is stolen, and which every other OpenPGP
 * implementation treats as revoking the whole certificate — left every unrevoked signing subkey
 * under it still trusted. A thief holding the stolen subkey kept a green VERIFIED badge in this
 * client after the owner had published the revocation.
 */
```

### `.filter { it.isMasterKey || hasValidBindingSignature(primary, it) }`
```
                // A subkey counts only if the PRIMARY key vouches for it. BouncyCastle's
                // PGPPublicKeyRing constructor stores subkeys without ever verifying their binding
                // signatures, so an attacker who supplies the armored blob — and on the
                // client-protected read path the relay does supply it, see PgpPayloadClient — could
                // append an arbitrary subkey to a genuine contact's key. Its key id then landed in
                // this set, PgpDecryptor.verifyOnePass looked the signer up by that same id in the
                // same blob, found the grafted key, and the signature verified: a message signed by
                // the attacker, attributed to a contact whose primary fingerprint the user had
                // compared in person.
                //
                // PgpFingerprint.compute has enforced exactly this since it was written, and its
                // KDoc says why. Two functions in one package answering "is this subkey part of
                // this key" differently is how the gap survived; they now share one implementation.
```

### `private fun org.bouncycastle.openpgp.PGPPublicKey.canSign(`
```
/**
 * Whether this key advertises a signing capability, per key flags [primary] asserted.
 *
 * `PGPPublicKey.isEncryptionKey()` is BouncyCastle's algorithm-level question and is the wrong one:
 * it answers "can this algorithm encrypt", not "did the owner authorise this key to sign". The key
 * flags in the self/binding signature are where that is stated, so they are what is read — and a
 * key with no key-flags subpacket at all falls back to the algorithm, which is the pre-RFC4880
 * behaviour every other client uses for old keys.
 */
```

### `private fun org.bouncycastle.openpgp.PGPPublicKey.keyFlagsAssertedBy(`
```
/**
 * The OR of every key-flags subpacket [primary] asserted about this key, or 0 if it asserted none.
 *
 * Two filters, both load-bearing:
 *
 * - **Signatures made by [primary] only.** `PGPPublicKey.signatures` yields third-party
 *   certifications too, and anyone can append one to an armored blob. Reading flags out of those
 *   would let whoever supplies the key material assert that an encryption-only key may sign, which
 *   is the capability check this function exists to perform.
 * - **Hashed subpackets only.** An unhashed area is not covered by the signature, so a flag placed
 *   there is editable without invalidating anything and must not grant a capability.
 */
```

### `internal data class LocalSignerKey(val publicKey: String, val confirmed: Boolean)`
```
/**
 * A signer key this device holds **itself**, out of its own contact store.
 *
 * The distinction from [SignerKey] is provenance and it is the whole point: a [SignerKey] arrives
 * in the relay's HTTP response, one field away from the ciphertext; a [LocalSignerKey] came out of
 * Room, where it got there through contact sync and had its fingerprint computed locally by
 * [PgpFingerprint.compute].
 *
 * [confirmed] means the user compared this exact fingerprint out of band — the QR ceremony — and
 * neither of the two local alarms is outstanding against it. It is the **only** input that can
 * produce [PgpSignatureState.VERIFIED_CONFIRMED]. Nothing on the wire can.
 */
```

### `internal fun interface LocalSignerKeyLookup {`
```
/**
 * Resolves the keys this device holds for an address, so the verdict does not have to take the
 * relay's word for who a sender is.
 *
 * A `fun interface` with no Android types, for the same reason [PayloadSource] is one: it keeps
 * [EncryptedMessageReader] free of Room and of a `Context`, so the exit table stays a JVM test.
 */
```

### `internal fun signatureStateFor(`
```
/**
 * The signature verdict, resolved **locally first**.
 *
 * ## What changed and why
 *
 * This function used to take only [serverKeys], and those arrive in the same JSON body as the
 * ciphertext: the relay chose the armored key, the address it is bound to, AND the `verified`
 * boolean. So a compromised or hostile relay signed a message with a key of its own, shipped that
 * key with `verified = true`, and this app rendered "✅ signature confirmed" beside a
 * `resolvedSender` the same response had also chosen. That is the exact adversary the
 * client-protected read path exists for, and the badge asserting the strongest claim in the app was
 * the one thing still delegated to it. Meanwhile `ContactEntity.pgpKeyFingerprint` — computed on
 * this device, from the key's own bytes, precisely so a server-supplied fingerprint is never
 * trusted — was sitting unread.
 *
 * ## The rule
 *
 * - **This device holds a key for the sender** ([localKeys] non-empty): the relay gets no say.
 *   The signature either matches a locally-held key or it does not, and if it does not while we
 *   hold one, that is [PgpSignatureState.KEY_CHANGED] — the sender rotated, or someone else signed.
 *   Both deserve the same "do not act on this yet" treatment, and the two are not locally
 *   distinguishable.
 * - **It does not** ([localKeys] empty): fall back to [serverKeys], which is still worth something
 *   — it is how a first-contact message says anything at all — but the verdict is **capped at
 *   [PgpSignatureState.VERIFIED_SEEN_BEFORE]**. `verified` off the wire is ignored outright.
 *
 * The cap is the part that must not be softened later. "Seen before" claims continuity, which a
 * relay-supplied key can honestly support; "confirmed" claims identity, which only the user's own
 * out-of-band comparison can.
 */
```

### `if (serverKeys.any { it.conflict }) return PgpSignatureState.KEY_CHANGED`
```
    // A conflict outranks a good key for the same sender. Two entries for one address means one of
    // them is a key that changed, and reporting the survivor as verified would hide precisely the
    // event worth reporting.
```

### `private fun verdictFor(signature: RawSignature, confirmed: Boolean): PgpSignatureState =`
```
/**
 * The verdict once the signing key has been matched to the sender, for a key whose out-of-band
 * confirmation status is [confirmed].
 *
 * Matches on [RawSignature]'s type rather than on its `valid` boolean, which is the whole reason
 * that type stopped being a pair of booleans. [RawSignature.NoSuchKey] must never reach
 * [PgpSignatureState.INVALID]: nothing was checked, so there is nothing to accuse anyone of.
 * Reaching it here means the key id matched a key we hold while the decryptor was not offered that
 * key — unreachable today, since [EncryptedMessageReader] offers local keys first, and reported
 * honestly rather than assumed away.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/VaultOpener.kt

### `internal sealed class OpenOutcome {`
```
/**
 * The result of unsealing the device envelope.
 *
 * [Opened] carries **no key material**, mirroring [VaultSealer]: the plaintext goes straight into
 * [EnrollmentSession] and the caller is told only that it worked, so no key material passes back
 * through the state machine.
 *
 * [Cancelled] is not a failure — the user dismissed the prompt, or the hosting Activity went away.
 * The reader returns to offering the Decrypt button and says nothing.
 */
```

### `internal interface VaultOpener {`
```
/**
 * The unseal, behind an interface because `BiometricPrompt` is Activity-bound and the orchestrator
 * must stay free of Android imports. That seam is what makes "the user dismissed the prompt" a JVM
 * test with a fake rather than an instrumented one.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/VaultOpenerAndroid.kt

### `internal class AndroidVaultOpener(private val activity: FragmentActivity) : VaultOpener {`
```
/**
 * Opens the device envelope through a `BiometricPrompt.CryptoObject`, so the Keystore key's
 * `setUserAuthenticationRequired(true)` is satisfied by the same authentication the user just
 * performed.
 *
 * **This is [EnrollmentSession]'s first writer.** Decision 6 of the enrollment ceremony left the
 * holder without one on purpose: filling a process-scoped holder with the account's private key for
 * zero readers is exposure bought for nothing. The reader now exists.
 *
 * The plaintext is written into the holder here rather than returned, so it never passes back
 * through whatever orchestrator calls [open].
 */
```

### `private sealed class VaultUnlock {`
```
    /**
     * The handoff between the two `withContext` blocks in [open].
     *
     * `withContext` is a regular suspend function, not `inline` — a bare `return` from inside its
     * lambda cannot leave [open] the way it could from an `inline` block, so the three early exits
     * on the IO side ([OpenOutcome.NoSecureLockScreen], [OpenOutcome.NotEnrolled], the `Failed` from
     * an unopenable cipher) have to travel out as a value instead. [Ready] carries what the Main
     * side needs next; [Blocked] carries the outcome straight through.
     */
```

### `val unlock = withContext(Dispatchers.IO) {`
```
        // Everything down to openCipher() is disk and Keystore work, never Main. buildPrefs() is a
        // MasterKey Keystore round trip plus an EncryptedSharedPreferences.create — a Tink keyset
        // disk read and a Keystore unwrap — against the `device_envelope_secure` file. That is a
        // different file from the pairing store, so no earlier IO hop in the app has warmed it: the
        // first call per process pays this cold path in full. openCipher(iv) adds
        // `KeyStore.load(null)`, `getKey` and a `Cipher.init` on a user-auth-required, StrongBox-
        // preferred key — tens to hundreds of milliseconds on real hardware. This is the same
        // workload `AndroidEnrollmentTransport.pairing()`'s KDoc describes for the pairing store:
        // "Blocking, and never to be called from the main thread."
        //
        // Only the suspendCancellableCoroutine block below needs Main, because BiometricPrompt
        // .authenticate performs a FragmentManager transaction. The hop to Main has to be explicit
        // here rather than inherited from the caller: EmailDetailActivity.encryptedReader(), the one
        // caller today, builds this port from inside its own withContext(Dispatchers.IO), so without
        // this the prompt would be requested from IO, not Main.
```

### `if (!hasSecureLockScreen(activity)) {`
```
            // hasSecureLockScreen(), not vault.ensureKey() — deliberately, not an oversight. ensureKey()
            // mutates: on a key that no longer inspects as matching spec, including a key that simply
            // fails to inspect, EnrollmentVault.existingKeyMatchesSpec() treats that as a mismatch and
            // ensureKey() falls through to generate(), which opens with prefs.edit().clear().commit() —
            // wiping the stored ciphertext before minting the new key. That mutation is only safe at the
            // seal, where a fresh key is about to be used regardless of what generate() just cleared.
            // Calling ensureKey() here, on the read path, would let a transient Keystore inspection
            // failure silently destroy a still-good envelope and report NotEnrolled over what should
            // have been Failed — this is the exact hazard hasSecureLockScreen's own KDoc names, almost
            // verbatim, at EnrollmentPortsAndroid.kt:140-145 ("Using it as a read-only probe would mean
            // opening the ceremony screen could destroy an existing enrollment. The vault still has the
            // final word at the seal, where a mutation is expected."). probeEnrollment
            // (EnrollmentState.kt:22-38) is the same non-mutating pattern used here: stored() and
            // openCipher(), never ensureKey(). Do not "simplify" this back to ensureKey() without
            // re-reading that KDoc.
```

### `val cipher = vault.openCipher(iv)`
```
            // stored() non-null but openCipher() null is an invalidated/unusable key over a real blob —
            // Failed, not NotEnrolled, matching probeEnrollment's KEY_INVALIDATED case (EnrollmentState
            // .kt:31). NotEnrolled must mean "no blob was ever stored here", never "a blob exists but
            // this key can't open it" — the two need different user-facing advice (re-enrol vs. nothing
            // to do).
```

### `if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||`
```
                // A prompt requested after the FragmentManager has saved its state — the user
                // backgrounds the app the instant the reader starts unsealing, landing here after
                // onSaveInstanceState — is silently dropped by BiometricPrompt.authenticateInternal:
                // no exception, no callback, ever. Without this guard the continuation above would
                // never resume and open() would hang forever behind a spinner with no prompt and no
                // error. Mirrors DeviceEnrollmentActivity.vaultSealer.seal()'s identical guard, in the
                // same place — first thing inside the coroutine, before the prompt is built — and
                // Cancelled for the same reason every other BiometricPrompt outcome that isn't a real
                // unseal failure resolves to Cancelled: nothing is broken, the user can try again.
                //
                // This guard has to stay inside the coroutine, on Main, evaluated as late as
                // possible before authenticate() — not hoisted above the IO hop, and not evaluated
                // once before the withContext(Main) switch. It has to run on the thread that is
                // about to call authenticate(), right before that call, or the race it closes reopens:
                // a save-state transition between the check and the call would still get silently
                // dropped.
```

### `val plaintext = authenticated.doFinal(ciphertext)`
```
                                // A GCM tag failure on doFinal means this ciphertext does not belong
                                // to this key — that is a real Failed, not a crash, and not something
                                // a retry fixes: the caller is told to re-enrol.
```

### `EnrollmentSession.putUtf8(plaintext)`
```
                                // putUtf8, not put(String(...)): a String copy of the private key
                                // cannot be zeroed. Decoding straight into the holder's CharArray
                                // leaves nothing behind that the holder cannot wipe.
```

### `override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {`
```
                        /** The user dismissing the prompt, or the library giving up on its own
                         *  (lockout, timeout). Every case maps to [OpenOutcome.Cancelled], never
                         *  [OpenOutcome.Failed]: none of them says the envelope itself is broken, only
                         *  that this attempt did not go through. Mirrors
                         *  `DeviceEnrollmentActivity`'s `vaultSealer.seal()`, whose own
                         *  `onAuthenticationError` resolves the same way for the same reason. */
```

### `val info = BiometricPrompt.PromptInfo.Builder()`
```
                // DEVICE_CREDENTIAL is allowed because the vault key itself allows it: EnrollmentVault
                // .generate() calls setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or
                // AUTH_DEVICE_CREDENTIAL), and a PromptInfo narrower than that fails at authenticate().
                // Matches DeviceEnrollmentActivity.vaultSealer.seal()'s own PromptInfo exactly. With
                // DEVICE_CREDENTIAL in the set, setNegativeButtonText must NOT be called —
                // BiometricPrompt throws if both are given.
```

### `prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))`
```
                // The Cipher above was constructed on IO, a moment ago; a Keystore-backed Cipher
                // carries no thread affinity, so handing it to a CryptoObject built and consumed on
                // Main is safe in principle. Flagged as device-verify in the task-16 report rather
                // than asserted outright — this is the kind of boundary that stays fine until a
                // future AndroidKeyStore provider quietly makes it not.
```

## app/src/main/java/org/kysecurity/mail/pgp/WebmailDeepLink.kt

### `fun webmailMessageUrl(serverUrl: String, mailbox: String, messageId: String): String? {`
```
/**
 * Builds the webmail URL that opens one specific message.
 *
 * The route already exists and is what a web push notification click uses: ReadPage reads
 * `?message=<id>` (optionally `&tab=`) alongside `?mailbox=`, opens that message once its tab has
 * loaded, then strips both params from the address bar. `tab` is omitted here — without it
 * ReadPage searches every tab, which is what we want since the relay's tab names and the web's
 * are not guaranteed to line up.
 *
 * INBOX is sent as an absent `mailbox` param rather than the literal string, matching the links
 * the web app builds for itself (its own Inbox link is a bare `/read`, and it treats an empty
 * mailbox as the default).
 *
 * Returns null when [serverUrl] isn't a usable absolute URL, which callers render as "no button"
 * rather than a dead one.
 */
```

### `fun webmailDraftsUrl(serverUrl: String): String? {`
```
/**
 * The webmail URL that opens the Drafts mailbox, used after handing a client-custody composition
 * off to the browser.
 *
 * It targets the mailbox rather than one specific draft because `POST /api/mail/draft` answers with
 * a bare `{ok: true}` and no UID — there is nothing to deep-link to. The draft the user just saved
 * is the newest one there.
 *
 * Unlike INBOX in [webmailMessageUrl], Drafts is passed explicitly: an absent mailbox means INBOX
 * to the web app's read page.
 */
```

### `fun webmailHomeUrl(serverUrl: String): String? =`
```
/**
 * The account's webmail home.
 *
 * Used by the Security page's "open webmail" actions, where the destination is "your account in the
 * browser" rather than one message — creating a PGP identity and choosing client custody are both
 * web-session-only actions on the backend.
 *
 * The path is replaced rather than appended: the stored `serverUrl` is the pairing's origin, but a
 * value carrying a path would otherwise produce `…/read/` and land nowhere. `isFirstPartyWebmailUrl`
 * still gates the launch on the origin.
 *
 * The query and fragment are cleared alongside the path: `encodedPath` alone leaves any `?...` or
 * `#...` on the input untouched, so a stored URL carrying one (there is no reason one would, but
 * nothing rules it out) would otherwise survive into the handoff target the same way a path would.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/WebmailOrigin.kt

### `fun isFirstPartyWebmailUrl(serverUrl: String, candidateUrl: String): Boolean {`
```
/**
 * Whether [candidateUrl] belongs to the same origin as the paired server.
 *
 * The gate on the webmail handoff. Every caller builds its URL from the pairing's own `serverUrl`,
 * and this refuses anything else rather than trusting that: the handoff is the one place the app
 * tells the user "this is your mail, sign in here", so an attacker-chosen URL reaching it is a
 * credential-harvest primitive. Compares the whole origin — scheme, host and port — not the host
 * alone.
 *
 * Uses OkHttp's [HttpUrl] rather than `android.net.Uri` so it is unit-testable on a plain JVM,
 * matching [webmailMessageUrl] in `WebmailDeepLink.kt`. [HttpUrl] additionally refuses any
 * non-http(s) scheme outright, so `javascript:` and `data:` never reach the comparison.
 */
```

### `NATIVE_APP,`
```
    /**
     * Offer the URL to a non-browser app — in practice the webmail PWA.
     *
     * Ranked first because it is the best experience available: a standalone window with the
     * session it holds, and no browser chrome.
     */
```

### `EXTERNAL_BROWSER,`
```
    /**
     * A plain `ACTION_VIEW` intent — the user's browser, in the browser's own task.
     *
     * Whether *any* handler exists cannot be determined in advance — see the note on
     * `resolveActivity` in this plan's constraints — so this mode means "attempt it and catch
     * the failure", not "a handler is known to exist".
     */
```

### `fun webmailLaunchOrder(isFirstParty: Boolean): List<WebmailLaunchMode> =`
```
/**
 * The modes to try, best first, until one of them actually launches.
 */
```

## app/src/main/java/org/kysecurity/mail/pgp/WebmailTab.kt

### `fun openWebmail(activity: Activity, serverUrl: String, url: String): Boolean {`
```
/**
 * Opens one of this account's own webmail URLs in a **separate task**: the installed PWA if there
 * is one, otherwise whatever browser the device has. [webmailLaunchOrder] owns that order; this
 * walks it and stops at the first mode that actually launched.
 *
 * It is not an in-app WebView, and that is deliberate — the user's real browser carries the
 * session cookies webmail already holds, so there is no second login, and this app cannot read its
 * contents or its account-password field.
 *
 * **There is no Custom Tab path, and that is the security property.** A Custom Tab is the
 * browser's activity launched into *this* app's task, and `FLAG_SECURE` is per-window: the blanket
 * one [org.kysecurity.mail.security.LockedActivity] sets on every KyPost window does not reach the
 * browser's. The Recents card would then show decrypted message content, on the one app whose every
 * other screen is blank there. All the tab bought was a back gesture instead of a task switch.
 *
 * Only ever called with a URL built from the pairing's own `serverUrl`; [isFirstPartyWebmailUrl]
 * enforces that rather than trusting it.
 *
 * @return true if something was launched. False means the caller should tell the user it could not
 *   open, and is *not* the same as the user dismissing the browser.
 */
```

### `Log.e(TAG, "Refused to open a URL that is not this account's webmail")`
```
        // A programming error, not a user condition: every caller builds this URL from the
        // pairing. Logged loudly so it surfaces rather than looking like a dead button. Nothing
        // below runs, so a refused URL never reaches the system at all.
```

### `private fun webIntent(url: String): Intent =`
```
/**
 * `ACTION_VIEW` + `CATEGORY_BROWSABLE` — a *web intent* in the platform's sense, which is what
 * makes firing it implicitly safe.
 *
 * The category is the security control here, not decoration. Android's domain-verification gate
 * applies **only** to web intents: an app that declares `<data android:scheme="https"
 * android:host="<the paired server>"/>` with no verified `assetlinks.json` is excluded from
 * resolution only when the intent carries BROWSABLE. Without it, any installed app may claim the
 * paired server's host and answer this handoff with a convincing fake webmail login — a credential
 * harvest aimed at the one screen a client-custody account has no alternative to. `openExternally`
 * in `EmailDetailActivity` adds the category for the same reason, and a browser gets it too.
 *
 * It costs nothing on the PWA path: a WebAPK's VIEW filter, like any app link's, is *required* to
 * declare BROWSABLE, and an intent's categories only narrow the match to filters that declare them.
 * Adding it can exclude only components that never declared it — precisely the set to exclude.
 */
```

### `private fun launchNonBrowser(activity: Activity, url: String): Boolean =`
```
/**
 * [WebmailLaunchMode.NATIVE_APP]: offer the URL to the webmail PWA, and fail if only browsers want
 * it.
 *
 * `FLAG_ACTIVITY_REQUIRE_NON_BROWSER` (API 30; this app is `minSdk 31`) is what makes the
 * preference real instead of a guess. The system resolves it at launch time and throws
 * `ActivityNotFoundException` when every candidate is a browser, so a miss costs one caught
 * exception and falls through to the browser.
 */
```

### `private fun launchExternalBrowser(activity: Activity, url: String): Boolean =`
```
/**
 * [WebmailLaunchMode.EXTERNAL_BROWSER]: the last resort. Same web intent as [launchNonBrowser]
 * without the non-browser flag, so a browser is exactly what answers it.
 *
 * Deliberately no `resolveActivity` guard. With `minSdk 31` and package-visibility filtering it
 * returns null for an implicit https intent even when a browser is installed, so guarding reported
 * "no webmail" to users who had one. Attempt the launch, catch the genuine no-handler case.
 */
```
