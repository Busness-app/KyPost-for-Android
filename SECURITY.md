# Security Policy

KyPost for Android is the companion app to a self-hosted KyPost server. It holds a
pairing credential for someone's mail account, caches their mail, and — depending on
settings — their contacts and attachments. This document covers how to report a
vulnerability and what the app does and does not protect.

For **server-side** security (TLS termination, reverse proxies, key custody at rest,
deployment hardening), see [SECURITY.md in the server
repository](https://github.com/Yoshiofthewire/kypost-server/blob/main/SECURITY.md).
Report server vulnerabilities there, not here.

## Reporting Security Vulnerabilities

Report vulnerabilities in the Android app via GitHub Security Advisories rather than
opening a public issue.

1. Go to the [Security
   Advisories](https://github.com/Yoshiofthewire/KyPost-for-Android/security/advisories)
   page
2. Click "Report a vulnerability"
3. Provide a description, affected versions, and reproduction steps if you have them
4. Do not disclose publicly until a patch is available

If you are unsure which repository a finding belongs to, file it here and it will be
moved. A misfiled report is better than an unfiled one.

### Disclosure Timeline

Matching the server repository, so a finding spanning both is not governed by two
different clocks:

- **Critical** (credential disclosure, authentication bypass, remote code execution):
  30 days
- **High** (privilege escalation, cryptographic weakness, local data disclosure past a
  security control): 60 days
- **Moderate** (denial of service, information disclosure): 90 days

You will get an acknowledgement within 2 business days, a severity assessment, and
credit in the release notes unless you prefer anonymity.

## What the app protects, and what it does not

Read this before relying on any single control. The app is deliberately honest about
where each one stops.

### App lock

A PIN or biometric gate on opening the app (`security/AppLockManager.kt`).

- Wrong-PIN attempts follow an escalating-delay curve: the first two are free, because
  typos happen, and attempt three onward adds a growing delay
  (`security/LockoutPolicy.kt`).
- After `WIPE_THRESHOLD` consecutive wrong attempts with no intervening success, local
  data is wiped (`security/SecurityWipe.kt`).
- Because an attacker gets a bounded number of guesses, common PINs are rejected at
  set time (`security/PinPolicy.kt`). The sequences and repeats that dominate published
  leaked-PIN datasets would otherwise all fit inside the free guesses.
- A PIN that cannot be *checked* — the Keystore pepper backing the verifier is gone or
  unusable — is deliberately distinct from a wrong PIN and **does not** count toward the
  wipe threshold. Folding the two together meant an OS-level Keystore invalidation made
  every correct PIN read as wrong, and destroyed user data in response to an event the
  user neither caused nor could avoid.

**What it does not do:** the app lock gates the app, not the device. It is not a defence
against an attacker with the device unlocked and the app already open.

### Hostile Location Protection

An opt-in mode (off by default) for users who expect their device to be inspected or
seized (`security/HostileLocationSettings.kt`).

When enabled:

- The Room database is constructed in-memory only, never disk-backed.
- Push history is held volatile rather than persisted.
- Device contact sync is blocked.
- Keyword settings are not persisted.
- Attachments are viewed ephemerally, with no disk write at all
  (`security/AttachmentAction.kt`, `security/EphemeralAttachmentProvider.kt`).

The flag is written with `commit()` rather than `apply()`, and *after* the on-disk
database has been deleted, so a process death cannot leave protection off while the user
believes it is on.

**Known limitation — attachments saved while HLP is off.** With protection off (the
default), a single tap writes an attachment to the shared Downloads collection, which is
outside the app sandbox. Nothing the wipe deletes reaches shared storage on its own, so
those files previously survived a wipe, an app-lock reset and a re-pair while the app
reported local data as cleared. `security/DownloadedAttachmentLedger.kt` exists to record
those MediaStore rows so the wipe can remove them. **Files a user has since moved,
copied, or opened into another app are beyond the app's reach entirely.**

### Certificate pinning

KyPost is self-hosted with a per-user server URL, so there is no certificate to hardcode.
The server's SPKI pin is captured once at pairing time and enforced on every later
connection (`security/SpkiPinner.kt`, `push/PinnedCallFactory.kt`).

**This is trust-on-first-use.** It detects a certificate that changes after pairing. It
cannot detect an attacker who is already in position *at* pairing. Pair over a network
you trust.

### Pairing credentials

The app authenticates to the server with a device id and a per-device secret
(`X-Kypost-Device-Id` / `X-Kypost-Device-Secret`, see `PairingAuthHeaders.kt`). The secret
is minted by the server at registration and returned exactly once.

- It is wrapped locally under a key derived from the app-lock PIN, peppered with a
  Keystore-held value (`security/CredentialCipher.kt`).
- It authorises push delivery, pull, contact sync, MFA response, and — where enabled —
  enrollment. It is **not** the account password and cannot be used to sign in to webmail.
- Revoke a lost device from the server's Security page. Revocation is per-device.

### Mail content and PGP

- **Encrypted mail is not decrypted in the app today.** PGP operations happen in webmail
  via Custom Tabs. See `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`.
- **Encrypted mail is excluded from push payloads by the server**, regardless of the
  Content Preview setting, because native push travels through a relay and on to FCM/APNs
  in cleartext at every hop.
- A device-sealed envelope for on-device decryption is accepted **gated behind Hostile
  Location Protection** — available only when HLP is off, and destroyed when HLP is
  turned on. The trade is recorded in full in the design spec above; it is a deliberate,
  user-chosen posture change, not a default.

### What is out of scope

- **A rooted or compromised device.** Keystore-backed material resists extraction, but an
  attacker with root and the app unlocked is inside every boundary here.
- **Screen capture and accessibility-service abuse** by other installed apps.
- **The mail server itself**, and anything reachable with the account password. Those are
  server-repository concerns.
- **Attachments after they leave the app**, as described above.

## Supported versions

`minSdk` is 31. Security fixes target the current release. There is no long-term support
branch for older versions.

## Security Contacts

- **Vulnerability reports:** [GitHub Security
  Advisories](https://github.com/Yoshiofthewire/KyPost-for-Android/security/advisories)
- **Maintainer:** [Yoshiofthewire](https://github.com/Yoshiofthewire)
- **Code of Conduct concerns** are handled separately — see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security vulnerabilities are not a Code of
  Conduct matter.
