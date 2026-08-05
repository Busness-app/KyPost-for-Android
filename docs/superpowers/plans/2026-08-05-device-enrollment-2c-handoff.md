# Device Enrollment 2c (Android) — Handoff

**Written:** 2026-08-05. **Server side (2a) is complete and merged into
`fix/security-audit-run-9` in kypost-server.** This document hands off the Android
client half.

---

## Read this first: the decision, and the requirement it creates

This design was **rejected on 2026-08-04** (commit `2ed6798`) and **accepted on 2026-08-05
as a user-visible choice gated behind Hostile Location Protection**. Both are recorded in
`docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`, in the section now
titled "Accepted, gated: a device-sealed envelope". Read it before starting — the objection
was not wrong, it was outweighed, and knowing which is which matters when you hit an edge
case.

**The reasoning.** The rejection weighed the device envelope against "the user has client
custody and types a passphrase". The real alternative is "the user never leaves server
custody at all", because the friction is what keeps them there. Against a **server-held
secret**, a secure-element envelope the user controls is a large improvement, and it is
what makes removing server custody adoptable. So the posture downgrade becomes an explicit
user choice rather than a designed-in default.

### The gate — this is a hard requirement, not a preference

- **HLP off (default):** the device envelope is available. The user may enroll, and may
  un-enroll at any time.
- **HLP on:** no device envelope. Enrollment is unavailable, and **enabling HLP must
  destroy any envelope that already exists**, along with its keystore key.

That last clause is the one to get right. `HostileLocationSettings.setEnabled`
(`security/HostileLocationSettings.kt`) is deliberately written *after* the on-disk
database has been deleted, and uses `commit()` rather than `apply()` so a process death
cannot leave the flag off while the user believes protection is on. **The envelope and its
keystore key must join that same teardown, under the same ordering.** An envelope that
survived the switch would leave the account's private key openable by device unlock on a
device whose owner has just declared they are somewhere hostile — the exact disclosure HLP
exists to prevent, and worse than what the original objection described.

Treat this as a first-class test target, not a cleanup detail: enable HLP with an active
enrollment, kill the process mid-teardown, and assert the envelope is gone and the marker
reports un-enrolled.

Lever C (rewrap under a separate PGP passphrase) is **not** superseded by this. It is what
an HLP-on user should be offered instead, since it gives client custody without a
device-openable envelope.

### What the SAS condition now means

The rejection set a user-verified short authentication string as a condition of revisiting.
It is now a condition of *shipping*. The server design
(`kypost-server/docs/superpowers/specs/2026-08-04-device-enrollment-design.md`) specifies
one and gets the direction right: **device displays, browser verifies**, because the
browser is where the secret moves. A device-side check would be too late — by the time the
phone finds it cannot open the envelope, the browser has already sealed to the attacker's
key.

The second half of that condition — binding the device id and PGP fingerprint into the
envelope's GCM AAD — is **not specified anywhere yet**. See "Unresolved spec gaps" item 3.
It is a shipping condition, not an optimisation.

---

## The server contract (implemented and verified)

These are the shapes as **built**, not as planned. Verified against the implementation.

### `POST /api/pgp/device/enrollment-key`

Publishes this device's enrollment public key.

- **Auth:** device credential headers only — `X-Kypost-Device-Id` /
  `X-Kypost-Device-Secret`. Not a session. Use `pairingAuthHeaders()`.
- **Body:** `{"publicKey":"<string>"}`. Read through a 4 KiB limit
  (`maxEnrollmentPublicKeyBytes`). Whitespace-trimmed; empty or blank → `400`.
- **Any `deviceId` in the body is ignored.** The device id comes from the verified
  credential. Do not bother sending one.
- **Success:** `200` → `{"ok":true}`.
- **Failure:** `401` on bad credentials; `429` with a `Retry-After` header when the
  device-auth lockout has tripped. Both come from the shared `writeDeviceAuthFailure`,
  so treat them exactly as `MfaResponseClient` already treats them.
- **Side effect:** stores the key plus a server-stamped RFC3339 UTC publish time.

The server does **not** validate that the string is a well-formed P-256 point. It is
stored opaquely and handed to the browser as-is. The encoding is therefore a
client-to-client contract that 2b and 2c must agree on independently — see gap 1.

### `GET /api/pgp/device/envelope`

Reads the one envelope sealed for this device.

- **Auth:** same device headers.
- **Takes no parameters.** The slot name is built server-side from the verified device
  record as `device:<deviceId>`. A `?slot=` query string is ignored — this is asserted by
  a test, deliberately, so it cannot quietly grow one.
- **Success:** `200` → `{"slot":"device:<deviceId>","envelope":"<opaque string>"}`.
- **Not found:** `404` → `{"error":"no envelope sealed for this device"}`. This is also
  what an **expired** transport copy returns; the two are indistinguishable to the client,
  by design.
- **Transport copies expire after 7 days** (`users.DeviceEnvelopeTTL`). A device that
  misses the window re-runs the ceremony; nothing is lost but the ceremony.

Only a *session* can create or delete a sealing. A device may publish a key and read what
was sealed for it, and nothing else.

### `POST /api/notifications/native/register` — new optional field

`encryptionEnrolled` (bool, optional) — the device's own answer to "can I still open my
enrollment envelope".

- Server-side it is a **pointer**: absent means *no opinion* and leaves the stored marker
  untouched; `true`/`false` set it. An older client that omits it is never silently marked
  un-enrolled.
- **The device must restate this on every registration call.** It is device-reported
  ground truth, not a record of what the browser did, because those diverge — an app
  reinstall destroys the keystore key, as does a biometric-enrollment change on some
  configurations. A marker that only ever turned on would tell the user a device is
  protected when it can read nothing.
- **Enabling HLP is one of those divergences.** The teardown destroys the envelope, so the
  device must report `false` at the next registration. Do not wait for the next natural
  registration to correct it — the Security page would show the device as protected in the
  window between, which is the specific lie this marker exists to prevent. Push a
  registration as part of the teardown, and treat a failure to reach the server as
  something to retry rather than drop, since the marker is now wrong in the unsafe
  direction.
- Add it in `push/NativeRegistration.kt` alongside `deviceToken` (`@SerialName`, line ~26).

### Three server behaviours worth relying on

- **The published key survives re-registration.** `upsertNativeDeviceTx` carries the
  enrollment columns forward on both re-registration branches (by device id, and by push
  token + platform). Publish once; an ordinary push-token rotation will not erase it.
  Regression-tested both branches.
- **The published key does NOT survive an identity change.** Any write or delete of the
  account's PGP identity clears `enrollmentPublicKey`, `enrollmentKeyAt` and
  `encryptionEnrolled` on every device — the key was published against a superseded
  identity, and every sealing made under it is void. **So the device must publish its key
  as part of starting enrollment, not only once at pairing.** A device that publishes only
  at pairing will find its key gone after the user rotates, and enrollment will fail with
  nothing on screen explaining why. The pairing itself is untouched: push, sync and the
  push-MFA approver flag all keep working across a rotation.
- **Publishing to an unknown device is an error, not a silent no-op.** Expect a `500` if
  the device row has been removed server-side while the credential still exists.

---

## Android anchors (verified to exist)

| What | Where |
|---|---|
| Device credential headers | `PairingAuthHeaders.kt` — `HEADER_DEVICE_ID`, `HEADER_DEVICE_SECRET`, `Request.Builder.pairingAuthHeaders(deviceId, deviceSecret)` |
| Pinned HTTP client | `PairingAuthHeaders.kt::pairingHttpClient`, `push/PinnedCallFactory.kt` |
| Closest client to model the two new ones on | `push/MfaResponseClient.kt` — device-authed POST, `pairingAuthHeaders`, `executeSync`, structured error extraction |
| Registration payload | `push/NativeRegistration.kt` (`encryptionEnrolled` goes here) |
| Pairing entry point — where "Enroll this device?" belongs | `push/PushPairingLinkActivity.kt` |
| Existing PGP surface | `pgp/` — note `PgpFingerprint.kt` (fingerprint formatting) and `PgpQrClient.kt` (the existing out-of-band verification pattern this ceremony is a sibling of) |
| `minSdk` | `app/build.gradle.kts:27` → **31**, so `PURPOSE_AGREE_KEY` is available on every supported device. Confirmed. |

The related on-device decryption spec plans a `pgp/PgpVault.kt`, `PgpEnvelope.kt`,
`PgpDecryptor.kt`. If both proceed, they share the vault and must be sequenced, not
written in parallel.

---

## The wire format — SETTLED, and binding on this client

These were open holes when this handoff was first written. They are now normative in
`kypost-server/docs/superpowers/specs/2026-08-04-device-enrollment-design.md`, under the
three `NORMATIVE:` headings, and implemented in the browser. **Read those headings — this
is a summary, not the contract.**

Three implementations must agree bit-for-bit. A disagreement does not fail loudly: it
fails as "the codes do not match" on every honest enrollment, which to a user is
indistinguishable from a hostile server.

**Public key encoding.** Base64 (standard alphabet, padded) of the uncompressed SEC1
point: `0x04 || X || Y`, X and Y each left-padded to exactly 32 bytes. 65 bytes raw, 88
characters encoded. From `ECPublicKey.getW()`, pad each coordinate to 32 bytes — do not
use `getEncoded()`, which gives DER.

**Code derivation.** Hash the **raw 65 bytes**, never the base64 text.

```
bucket   = floor(unixSeconds / 120)
preimage = rawKey(65) || uint16BE(len(deviceIdUtf8)) || deviceIdUtf8 || uint64BE(bucket)
H        = SHA-256(preimage)
code     = first 50 bits of H, MSB-first, as 10 Crockford base32 chars
           (alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ), displayed XXXXX-XXXXX
```

**Test vector — assert this exact string.** With `deviceId = "test-device"`,
`bucket = 14000000`, and a key of `0x04` then X = `0x01`×32, Y = `0x02`×32:

```
5R9K6FWA18        displayed as 5R9K6-FWA18
```

That key is a valid encoding but not a point on P-256, deliberately: the derivation hashes
bytes and must not need a curve operation, so the vector is reproducible before ECDH is
wired up. `frontend/src/lib/deviceEnrollment.test.ts` holds it as an inline snapshot and is
**authoritative if it and the design doc ever disagree** — it runs on every frontend build,
the document does not.

**Envelope.** JSON, `{"v":1,"alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":…,"iv":…,"ct":…}`.
HKDF-SHA256 with `ikm` = the ECDH shared secret, `salt` = the device's raw 65-byte public
key, `info` = UTF-8 `"kypost-device-envelope/v1"`, length 32. IV is 12 bytes; `ct` carries
the 16-byte GCM tag appended.

**AAD** = UTF-8 of `kypost-device-envelope/v1|<deviceId>|<pgpFingerprint>`, fingerprint
uppercase hex, no spaces. This is the binding this repo required before withdrawing its
rejection — device id stops replay at another device, fingerprint stops an envelope
outliving an identity rotation.

**Changing any of this is a wire-format break**, not a fix. It moves the `v1` tag, the HKDF
`info` and the AAD prefix together, and strands every enrolled device until it re-enrolls.

---

## Status of the server work

Complete, on `fix/security-audit-run-9` (which also contains 10 further security commits).
Four commits: `cd28b8f`, `bfd2c10`, `54b7daf`, `3b038fe`.

**Verified:** `go build`, `go vet`, `gofmt` clean; full non-race suite exit 0 across 30
packages; `-race` at CI's flags (`-timeout=20m`) green on `internal/api` (714s),
`internal/state`, `internal/users`. 17 new tests, with four mutation checks confirming the
critical ones fail when the behaviour is removed.

**One caveat carried forward:** the additive column migration I wrote had a cross-process
check-then-act race, fixed later on that branch by `0aa6083`. Every test opened a store
single-process in a `t.TempDir()`, so the two-process startup window was structurally
invisible to them, and `-race` would not have caught it either — it is cross-process, not
cross-goroutine. Worth knowing if 2c work leads anywhere near `state.Store`.

The branch is **not pushed** and has no PR as of this writing.
