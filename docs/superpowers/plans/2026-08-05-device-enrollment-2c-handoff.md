# Device Enrollment 2c (Android) — Handoff

**Repo:** `kypost-android` (this one). **Server (2a) + browser (2b):** PR #80 on `kypost-server`,
branch `perf/bound-lockout-tests` — **open and unmerged as of 2026-08-05**.
**Normative spec:** `kypost-server/docs/superpowers/specs/2026-08-04-device-enrollment-design.md`.

This merges the two handoffs that existed in parallel: the Android copy (which held the Hostile
Location gate and the anchors) and the kypost-server copy (which held the settled wire format, the
post-2b contract changes, and the test list). Where they disagreed, the later server copy wins,
except that nothing in it supersedes the HLP gate below — that section has no counterpart there.

---

## The security does not live here — and that is the point

2b is where the substituted-key attack is caught: the browser compares a code it derives from the
key **the server handed it** against a code the user reads off this device, and refuses to seal on
mismatch. This device's job is narrower and stricter:

- **Derive the code from the key in your own keystore.** Never from anything the server sent back,
  never from a cached copy of what you published. The moment this device derives from a
  server-supplied value, the comparison compares the server against itself and the whole feature is
  decoration.
- **Never let the private half leave the secure element.** `PURPOSE_AGREE_KEY`, non-extractable. If
  it can be exported, an attacker with the sealed envelope has the key.
- **Report your real state.** `encryptionEnrolled` is *your* answer to "can I still open my local
  envelope", and the browser renders it as "this device can read your encrypted mail". A marker
  that drifts optimistic is worse than none.

You are the ground truth the browser checks the server against. Be honest, be local.

---

## The Hostile Location gate — a hard requirement, not a preference

This design was **rejected on 2026-08-04** (commit `2ed6798`) and **accepted on 2026-08-05 as a
user-visible choice gated behind Hostile Location Protection**. Both are recorded in
`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`, under "Accepted, gated: a
device-sealed envelope". Read it before starting — the objection was not wrong, it was outweighed,
and knowing which is which matters when you hit an edge case.

The rejection weighed the device envelope against "the user has client custody and types a
passphrase". The real alternative is "the user never leaves server custody at all", because the
friction is what keeps them there. Against a **server-held secret**, a secure-element envelope the
user controls is a large improvement, and it is what makes removing server custody adoptable. So
the posture downgrade becomes an explicit user choice rather than a designed-in default.

- **HLP off (default):** the device envelope is available. The user may enroll, and may un-enroll
  at any time.
- **HLP on:** no device envelope. Enrollment is unavailable, and **enabling HLP must destroy any
  envelope that already exists**, along with its keystore key.

That last clause is the one to get right. `HostileLocationSettings.setEnabled`
(`security/HostileLocationSettings.kt`) is deliberately written *after* the on-disk database has
been deleted, and uses `commit()` rather than `apply()` so a process death cannot leave the flag
off while the user believes protection is on. **The envelope and its keystore key must join that
same teardown, under the same ordering.** An envelope that survived the switch would leave the
account's private key openable by device unlock on a device whose owner has just declared they are
somewhere hostile — the exact disclosure HLP exists to prevent, and worse than what the original
objection described.

Treat this as a first-class test target, not a cleanup detail: enable HLP with an active
enrollment, kill the process mid-teardown, and assert the envelope is gone and the marker reports
un-enrolled.

**Enabling HLP must also push a registration reporting `encryptionEnrolled: false`.** Do not wait
for the next natural registration — the Security page would show the device as protected in the
window between, which is the specific lie this marker exists to prevent. A failure to reach the
server is something to retry, not drop, because the marker is now wrong in the unsafe direction.

Lever C (rewrap under a separate PGP passphrase) is **not** superseded by this design. It is what
an HLP-on user should be offered instead, since it gives client custody without a device-openable
envelope.

---

## Do this first, before any UI

Assert the normative vector. One test, no dependencies, an hour of work:

```
deviceId  = "test-device"
bucket    = 14000000                    (unixSeconds 1680000000)
rawKey    = 0x04 ‖ X(0x01 × 32) ‖ Y(0x02 × 32)      // valid encoding, NOT on the curve
expected  = "5R9K6FWA18"                             // displayed 5R9K6-FWA18
```

**This vector has only ever been verified in the browser.** If Android disagrees, the failure mode
is that codes never match — and the browser reports that as *"the key this server gave the browser
is not the key on that device"*. An encoding bug presents to the user as an active attack. Find out
now, not during a ceremony.

The key is deliberately off-curve: derivation hashes bytes and must not require a curve operation,
so this stays reproducible before ECDH is wired up.

`frontend/src/lib/deviceEnrollment.test.ts` in kypost-server holds the same vector as an inline
snapshot and is **authoritative if it and the spec ever disagree** — it runs on every frontend
build; the document does not.

---

## Wire format — settled, do not renegotiate

Three implementations must agree bit-for-bit. A disagreement does not fail loudly: it fails as "the
codes do not match" on every honest enrollment, which to a user is indistinguishable from a hostile
server.

**Public key.** Base64 (standard alphabet, padded) of the uncompressed SEC1 point: `0x04 ‖ X ‖ Y`,
X and Y left-padded to exactly 32 bytes. 65 bytes raw, 88 characters encoded. Android:
`ECPublicKey.getW()` gives you X and Y to pad — **do not use `getEncoded()`**, which gives DER.

**Code derivation.** Hash the **raw 65 bytes**, never the base64 text.

```
bucket   = floor(unixSeconds / 120)      // integer division, UTC, no leap smear
preimage = rawKey(65) ‖ uint16BE(byteLength(deviceIdUtf8)) ‖ deviceIdUtf8 ‖ uint64BE(bucket)
H        = SHA-256(preimage)
code     = first 50 bits of H, MSB first, ten Crockford base32 chars
           alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ, char i = bits [5i, 5i+5)
display  = XXXXX-XXXXX
```

**`deviceId` is charset-bounded (added 2026-08-05, after 2b).** New ids must be **1–128 characters
of `A-Z a-z 0-9 . _ : -`**, and the server rejects anything else at registration. Every permitted
character is byte-identical under UTF-8, NFC and NFD. **Do not normalise `deviceId` before
hashing** — with this charset there is nothing to normalise, which is the point. The bound exists
because an NFC/NFD disagreement between two clients would surface to the user as a substituted key.

**Envelope** (browser → server → you), all fields base64:

```json
{ "v": 1,
  "alg": "ECDH-P256+HKDF-SHA256+A256GCM",
  "epk": "<raw ephemeral public key, 65 bytes, same encoding as above>",
  "iv":  "<12 bytes>",
  "ct":  "<AES-256-GCM ciphertext, 16-byte tag appended>" }
```

- **Shared secret:** ECDH(your private, `epk`) → 32 bytes.
- **KDF:** HKDF-SHA256, `ikm` = shared secret, **`salt` = your own raw 65-byte public key**,
  `info` = UTF-8 `"kypost-device-envelope/v1"`, length 32.
- **AAD** = UTF-8 of `kypost-device-envelope/v1|<deviceId>|<pgpFingerprint>`, fingerprint
  **uppercase hex, no spaces**.
- **Plaintext** = the armored PGP private key, UTF-8.

The AAD binding is a shipping condition, not an optimisation — it is what this repo required before
withdrawing its rejection. Binding `deviceId` stops an envelope minted for one device being
replayed at another; binding the fingerprint stops one surviving an identity rotation and
decrypting into a key the account no longer advertises. **If AAD verification fails, treat it as
hostile, not as a retry.**

**Changing any of this is a wire-format break**, not a fix. It moves the `v1` tag, the HKDF `info`
and the AAD prefix together, and strands every enrolled device until it re-enrolls.

---

## Server contract — implemented and verified

| Step | Route | Auth | Notes |
|---|---|---|---|
| Publish your public key | `POST /api/pgp/device/enrollment-key` | device headers | `{"publicKey":"<base64>"}`, ≤4 KiB. No step-up: a public key is not a capability. |
| Read your own envelope | `GET /api/pgp/device/envelope` | device headers | **No slot parameter exists.** The slot is built server-side from your verified credential. |
| Report your state | `POST /api/notifications/native/register` | pairing token | `encryptionEnrolled` is tri-state: omit it if you have no opinion. |

Device headers are `X-Kypost-Device-Id` and `X-Kypost-Device-Secret`.

**`POST /api/pgp/device/enrollment-key`** — body is whitespace-trimmed; empty or blank → `400`. Any
`deviceId` in the body is **ignored**; the device id comes from the verified credential. `401` on
bad credentials, `429` with `Retry-After` when the device-auth lockout trips — both from the shared
`writeDeviceAuthFailure`, so treat them exactly as `MfaResponseClient` already does. The server does
**not** validate that the string is a well-formed P-256 point; it is stored opaquely and handed to
the browser as-is, which is why the encoding above is a client-to-client contract.

**`GET /api/pgp/device/envelope`** returns `{"slot":"device:<id>","envelope":"<opaque string>"}`, or
**404** `{"error":"no envelope sealed for this device"}`. 404 covers both "never sealed" and
"expired" — indistinguishable by design, and both mean *re-run the ceremony*. A `?slot=` query
string is ignored, asserted by a test so it cannot quietly grow one.

**The server's copy expires after 7 days** (`DeviceEnvelopeTTL`). It is transport, not storage:
fetch it, re-seal locally, and stop depending on it. Nothing deletes it for you — expiry is lazy and
needs no caller, because inventing a device-authenticated delete would hand a device the power to
destroy a sealing. **Only a session may mint or destroy a sealing.**

### Three server behaviours worth relying on

- **The published key survives re-registration.** `upsertNativeDeviceTx` carries the enrollment
  columns forward on both re-registration branches (by device id, and by push token + platform).
  Publish once; an ordinary push-token rotation will not erase it. Regression-tested both branches.
- **The published key does NOT survive an identity change.** Any write or delete of the account's
  PGP identity clears `enrollmentPublicKey`, `enrollmentKeyAt` and `encryptionEnrolled` on every
  device. **So publish the key as part of starting enrollment, not only once at pairing.** A device
  that publishes only at pairing will find its key gone after the user rotates, and enrollment will
  fail with nothing on screen explaining why. The pairing itself is untouched.
- **Publishing to an unknown device is an error, not a silent no-op.** Expect a `500` if the device
  row has been removed server-side while the credential still exists.

### Two changes since 2b that will bite you

1. **Re-registration now requires your current device secret.** Rebinding an existing `deviceId` at
   `POST /api/notifications/native/register` returns **409** unless you send
   `X-Kypost-Device-Secret` with the request. If the FCM-token-refresh flow re-registers — and the
   `encryptionEnrolled` contract implies it does — **it must send that header**. A stolen session
   could otherwise take over the device row, keeping `MFAApprover` status and redirecting push.
2. **Device credentials are refused while the account owes a password change.** After an admin
   password reset, `deviceAuthFromRequest` rejects you until the user completes the change. Surface
   that as "sign in on the web to finish your password change", not as a pairing error.

---

## Android anchors (verified to exist, 2026-08-05)

| What | Where |
|---|---|
| Device credential headers | `app/src/main/java/com/urlxl/mail/PairingAuthHeaders.kt` — `HEADER_DEVICE_ID`, `HEADER_DEVICE_SECRET`, `Request.Builder.pairingAuthHeaders(deviceId, deviceSecret)` |
| Pinned HTTP client | `PairingAuthHeaders.kt::pairingHttpClient`, `push/PinnedCallFactory.kt` |
| Closest client to model the two new ones on | `push/MfaResponseClient.kt` — device-authed POST, `pairingAuthHeaders`, `executeSync`, structured error extraction |
| Registration payload | `push/NativeRegistration.kt` — `encryptionEnrolled` goes here, alongside `deviceToken` (`@SerialName`, line ~26) |
| Pairing entry point — where "Enroll this device?" belongs | `push/PushPairingLinkActivity.kt` |
| HLP teardown to hook | `security/HostileLocationSettings.kt` — `setEnabled` |
| Existing PGP surface | `pgp/` — note `PgpFingerprint.kt` and `PgpQrClient.kt`, the existing out-of-band verification pattern this ceremony is a sibling of |
| `minSdk` | `app/build.gradle.kts:27` → **31**, so `PURPOSE_AGREE_KEY` is available on every supported device |

**Note the path correction:** `PairingAuthHeaders.kt` sits at `com/urlxl/mail/`, not
`com/urlxl/mail/push/`. Earlier drafts of this handoff said `push/`.

The related on-device decryption spec plans a `pgp/PgpVault.kt`, `PgpEnvelope.kt`,
`PgpDecryptor.kt`. If both proceed, they share the vault and must be sequenced, not written in
parallel.

---

## The ceremony, end to end

1. Generate an EC P-256 keypair, `PURPOSE_AGREE_KEY`, StrongBox where the hardware allows, private
   half **non-extractable**.
2. Publish the public half under the existing pairing credential.
3. User starts enrollment. Display the code for the current bucket, refreshing on the boundary.
4. User types it into the browser. The browser verifies and, on match, seals and `PUT`s.
5. Fetch `GET /api/pgp/device/envelope`. Open by ECDH **inside the secure element**.
6. Re-seal locally under a secure-element AES-GCM key carrying `setUserAuthenticationRequired`.
   From here the server's copy is dead weight.
7. Report `encryptionEnrolled` on registration and every token refresh, based on whether you can
   **actually still open your local envelope** — not on whether you once could.

**Primary entry point is a prompt at pairing**, not a settings screen. Both screens are already in
front of the same person, and the attacker's grinding window collapses from days to seconds. The
device list on the Security page is the secondary path, for a device that declined or was paired
before this shipped.

---

## Failure handling

- **Declined at pairing** — nothing happens. Push and mail work exactly as before. Offer it again
  later; declining must not be a dead end.
- **Code expired** — mint a fresh one. The browser distinguishes expiry from mismatch and says so;
  do not make your copy contradict it.
- **Mismatch** — the browser refuses and explains. You have nothing to do; do not offer a retry that
  implies the user mistyped when the browser has just told them the server may be hostile.
- **Clock skew** — a device more than ~2 minutes **ahead** of the browser fails every attempt. The
  browser's copy names this. Keep your clock honest; do not widen your window to compensate.
- **AAD verification fails** — hostile or stale. Do not retry, do not fall back. Re-enroll.
- **Envelope 404** — expired or never sealed. Re-run the ceremony.
- **Identity rotated** — every sealing is invalidated by design. Report `encryptionEnrolled: false`
  and offer re-enrollment. Surface it as expected, not as an error.
- **Ordering** — enrollment must FOLLOW identity creation. Reversed, the envelope is silently
  discarded and the server cannot detect it, because both calls are individually valid and it cannot
  read either envelope. This is a client obligation. Test it.

---

## Tests that matter, in order

1. **The vector reproduces** — `5R9K6FWA18`. Before anything else.
2. **The code is derived from the keystore key**, not from anything the server returned. Mutate the
   source to a server-supplied value and prove the test fails.
3. **The private key cannot be exported.** Assert the key is non-extractable, and that a request for
   the raw private material throws.
4. **AAD mismatch refuses**, for both a wrong `deviceId` and a wrong fingerprint.
5. **The local re-seal requires user authentication** — `setUserAuthenticationRequired` holds.
6. **`encryptionEnrolled` follows reality down as well as up** — after the local key is destroyed
   (app reinstall, biometric change), it reports false.
7. **Re-registration sends the device secret** and survives a token refresh without a 409.
8. **Enrollment before identity creation** is rejected or retried, not silently lost.
9. **HLP teardown destroys the envelope and the keystore key**, survives process death mid-teardown,
   and pushes `encryptionEnrolled: false`.

Treat "there is a test for it" as unproven until you have broken the implementation and watched the
test go red. Two of 2b's security tests originally passed against implementations with the property
removed — one of them against the design's own headline attack — and were only caught because
someone mutated the code and re-ran them. See `1c74842` and `00feae6` in kypost-server.

---

## What 2c cannot fix, and should not pretend to

- **A live hostile server defeats the code.** It ships the browser's JavaScript and can serve a
  bundle that skips the comparison. This control defends against a server that retains too much, a
  stolen backup, or a compromised database. The browser UI says so in its own copy; do not write
  Android copy that claims more.
- **Once you re-seal locally, the server cannot revoke you.** Deleting the slot removes the
  transport copy only. Real revocation is identity rotation. Signal has the same property.
- **This concedes attacks by someone holding an unlocked device.** That is the trade the parent spec
  makes; `setUserAuthenticationRequired` is what narrows it.

---

## Build note for whoever picks this up

`./gradlew testDebugUnitTest` fails at configuration time with the configuration cache enabled:
dependency verification has no entry for `kotlinx-coroutines-bom-1.6.4.pom`, pulled into a detached
KSP configuration. `--no-configuration-cache` avoids it and the suite runs clean (511 tests as of
`d4768db`). Worth fixing properly in `gradle/verification-metadata.xml` rather than working around
forever, but it is not 2c's job and the entry should not be added without checking the artifact.

## Open question for 2d (Qt)

Whether the Qt clients can hold a non-extractable key is still unproven. If they cannot, they stay
on the passphrase tier — and that must not block 2c. Do not design Android around a shared
abstraction with a client that may never exist.
