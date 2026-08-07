# Reading Encrypted Mail on the Device — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an enrolled phone decrypt and read a client-protected PGP message locally, instead of sending the user to webmail.

**Architecture:** Part 0 fixes two `kypost-server` defects that make the feature invisible or dishonest — PGP flags dropped from the mail cache for client-protected messages, and signer keys shipped without their trust provenance. Part 1 adds six Android units (five pure-JVM, one Activity-bound port) that unseal the already-stored private key, fetch ciphertext from `/api/mail/pgp-payload`, decrypt with BouncyCastle, bind the signature to the displayed sender, parse the MIME, and render into the existing hardened WebView.

**Tech Stack:** Go 1.26.5 (`kypost-server/backend`); Kotlin/Android, BouncyCastle `bcpg-jdk18on:1.79`, `angus.mail` (`org.eclipse.angus:jakarta.mail:2.0.4`), OkHttp, kotlinx.serialization, JUnit4.

**Spec:** `docs/superpowers/specs/2026-08-07-on-device-encrypted-mail-reading-design.md`

## Global Constraints

- **The decrypted body never reaches Room, and never `fetchedBodyHtml`.** `fetchedBodyHtml` feeds reply quoting → `ComposeDraftCache` → `POST /api/mail/draft`, which uploads to the server.
- **`PgpDecryptor` and `PgpMimeReader` must have zero Android imports.** Use BouncyCastle's lightweight `Bc*` operators, never `Jce*` — Android ships a stripped "BC" provider that collides with the full one. No `android.util.Base64`; use `java.util.Base64`.
- **`isReturnDefaultValues = true` is set project-wide** (`app/build.gradle.kts:74`). **Every new test must be proven by deliberate break** — invert the assertion, watch it fail, restore it. A test that resolves against a stubbed `android.jar` passes against an implementation that does nothing.
- **`connectedDebugAndroidTest` fails with `No connected devices!`**, which looks like a failing assertion. Confirm a red is an assertion before treating it as evidence.
- **This repo has no mocking framework.** Hand-write fakes; follow `app/src/test/java/com/urlxl/mail/pgp/FakeEnrollmentPorts.kt`.
- **Top-level test fakes are `internal`, never `private`** — Kotlin compiles a top-level `private` class to a package-level JVM name, and a second file declaring the same name fails as a duplicate class.
- **A conflicted signer key is never offered to the signature check.** It crosses the wire only so the client can report `KEY_CHANGED`.
- Android unit tests: `./gradlew :app:testDebugUnitTest --tests "<pattern>"`. Go tests: run from `kypost-server/backend`, `go test ./internal/...`.

---

## File Structure

**`kypost-server` (Part 0)**

| File | Responsibility |
|---|---|
| `backend/internal/mailcache/store.go` | Modify `Upsert` existing-UID branch (line ~458) — widen the PGP-flag guard |
| `backend/internal/mailcache/store_test.go` | Add round-trip tests for the widened guard |
| `backend/internal/api/server_inbox.go` | Modify delta write-back (line ~504) — widen the same guard |
| `backend/internal/api/pgp_receive.go` | `boundSignerKey` gains `Verified`/`Source`/`Conflict`; `boundSignerKeys` stops discarding them |
| `backend/internal/api/pgp_receive_test.go` | Provenance and conflict tests |

**`kypost-android` (Part 1)**

| File | Responsibility |
|---|---|
| `app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt` | Pure JVM: armored key + payload → plaintext bytes + raw signature verdict |
| `app/src/main/java/com/urlxl/mail/pgp/PgpMimeReader.kt` | Pure JVM: decrypted bytes → body HTML/plain |
| `app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt` | Pure function: signer keys + sender + raw verdict → `PgpSignatureState` |
| `app/src/main/java/com/urlxl/mail/pgp/PgpMessageState.kt` | Modify: expand `PgpSignatureState` to six states; update `pgpSignatureStateOf`, `pgpRowMarker` |
| `app/src/main/java/com/urlxl/mail/pgp/PgpPayloadClient.kt` | `GET /api/mail/pgp-payload` on the pinned pairing call factory |
| `app/src/main/java/com/urlxl/mail/pgp/VaultOpener.kt` | Port + `OpenOutcome`, mirroring `VaultSealer` |
| `app/src/main/java/com/urlxl/mail/pgp/VaultOpenerAndroid.kt` | `BiometricPrompt` implementation of the port |
| `app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt` | Orchestrator; no Android imports; returns the exit table |
| `app/src/main/java/com/urlxl/mail/KyPostApp.kt` | Modify: add `onTrimMemory` → `EnrollmentSession.clear()` |
| `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt` | Modify: padlock, Decrypt button, six signature states, disabled reply/forward |
| `app/src/main/res/drawable/ic_lock_large.xml` | New padlock vector |
| `app/src/main/res/layout/activity_email_detail.xml` | Modify: padlock placeholder view + Decrypt/Retry buttons |
| `app/src/main/res/values/strings.xml` | Modify: new and corrected strings |
| `app/src/main/AGENTS.md` | Modify: the "no on-device private key" contract is obsolete |

---

# Part 0 — kypost-server

### Task 1: The PGP flags survive an empty body for client-protected messages

**Files:**
- Modify: `backend/internal/mailcache/mailcache.go` — add `PGPDecryptError string \`json:"-"\`` to `Entry`
- Modify: `backend/internal/mailcache/store.go:458`
- Modify: `backend/internal/api/server_inbox.go:504` and `mailCacheEntryFromUnreadMessage` (~:196)
- Test: `backend/internal/mailcache/store_test.go`

**Prerequisite the first draft of this plan missed.** `mailcache.Entry` has `PGPEncrypted`,
`PGPSigned`, `PGPVerified`, `PGPSignerFingerprint`, `PGPVerdictSchemaVersion` and `ContactKeyGen`
— but **no `PGPDecryptError`**. Without it the guard below cannot compile, and more importantly it
could not do its job: at the `Upsert` boundary a client-protected message and a failed decrypt are
both "encrypted, no body", and nothing distinguishes them.

Add the field as a **transient signal that is never persisted**:

```go
	// PGPDecryptError is the transient outcome of the caller's decrypt
	// ATTEMPT, not durable state — hence `json:"-"`, unlike every other
	// field here.
	//
	// It exists so Upsert can tell two bodyless cases apart. A
	// client-protected message is encrypted and bodyless because the server
	// deliberately does not decrypt it, and that classification is a stable
	// fact worth caching. A FAILED decrypt is also encrypted and bodyless,
	// and may be transient, so caching it would make one bad moment stick
	// until the entry rolls out of the window.
	//
	// Never written into a stored entry: read by the guard, then discarded.
	// Persisting it would be the stale-error bug in a different place.
	PGPDecryptError string `json:"-"`
```

Three consequences, all in scope:

1. The existing-UID branch reads `in.PGPDecryptError` for the guard and never copies it to `updated`.
2. The new-UID branch does `e := in`, which copies it — set `e.PGPDecryptError = ""` there, so it
   stays out of the in-memory window as well as off disk.
3. `mailCacheEntryFromUnreadMessage` must copy `msg.PGPDecryptError`, or the classic (non-delta)
   path hands `Upsert` an entry that always looks like a clean classification and the guard caches
   failed decrypts there.

**Interfaces:**
- Consumes: nothing.
- Produces: `mailcache.Entry.PGPEncrypted` is now durable for client-protected messages. Part 1 depends on it reaching the phone as `pgpEncrypted: true`.

**Background.** Both sites gate the PGP flags on `Body != ""`. The stated reasoning — "PGP fields are only ever known alongside a freshly fetched body" — holds for server-protected accounts and inverts for client-protected ones, where a *correct* classification always arrives with an empty body because the server deliberately does not decrypt. Result: `cache.Sync` creates the entry from `ListOverviews` (no PGP data) at `PGPEncrypted = false`, the write-back that would correct it is skipped, and every poll after the first reports the message as ordinary mail.

- [ ] **Step 1: Write the failing tests**

Add to `backend/internal/mailcache/store_test.go`:

```go
// A client-protected message is encrypted AND has no body, by design — the
// server does not decrypt it. The flags must survive an Upsert into an
// existing entry anyway, or the message is cached as ordinary mail and the
// phone never offers to decrypt it.
func TestUpsertKeepsPGPFlagsForBodylessClientProtectedMessage(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	// The poller/Sync creates the entry first, from overviews, with no PGP data.
	if err := s.Upsert("INBOX", []Entry{{UID: 7, MessageID: "7", Subject: "..."}}); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	// Then the API warms it with the classification and no body.
	if err := s.Upsert("INBOX", []Entry{{
		UID: 7, MessageID: "7", Subject: "...",
		Body:         "",
		PGPEncrypted: true,
	}}); err != nil {
		t.Fatalf("warm upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if !entries[0].PGPEncrypted {
		t.Fatal("PGPEncrypted was dropped for a bodyless client-protected message")
	}
}

// The other half of the original comment is real: a FAILED decrypt also
// leaves an empty body, and caching that would make a transient failure
// sticky. Only a clean classification is durable.
func TestUpsertStillDropsFlagsWhenDecryptFailed(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Upsert("INBOX", []Entry{{UID: 8, MessageID: "8"}}); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	if err := s.Upsert("INBOX", []Entry{{
		UID: 8, MessageID: "8",
		Body:            "",
		PGPEncrypted:    true,
		PGPDecryptError: "no secret key",
	}}); err != nil {
		t.Fatalf("warm upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].PGPEncrypted {
		t.Fatal("a failed decrypt was cached; it must stay uncached and retryable")
	}
}

// The error is a signal for the guard, not durable state. If it survived
// into the window, a transient failure would keep suppressing the flags
// long after the decrypt would have succeeded.
func TestUpsertNeverStoresADecryptError(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Upsert("INBOX", []Entry{{
		UID: 9, MessageID: "9", PGPEncrypted: true, PGPDecryptError: "no secret key",
	}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].PGPDecryptError != "" {
		t.Fatalf("a decrypt error was stored: %q", entries[0].PGPDecryptError)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/mailcache/ -run 'TestUpsertKeepsPGPFlags|TestUpsertStillDrops' -v
```

Expected: `TestUpsertKeepsPGPFlagsForBodylessClientProtectedMessage` FAILS with "PGPEncrypted was dropped…". `TestUpsertStillDropsFlagsWhenDecryptFailed` PASSES already (it is the guard against over-correcting in Step 3).

- [ ] **Step 3: Widen the guard in `mailcache/store.go`**

Replace line 458's `if in.Body != "" {` and amend the comment above the PGP block:

```go
		// The body is the sentinel for a freshly fetched message, but it is NOT
		// the only evidence of a correct classification. A client-protected
		// message is encrypted AND bodyless by design — the server deliberately
		// does not decrypt it — so gating on the body alone filtered the flags
		// out of exactly the messages end-to-end custody exists for, and the
		// phone cached them as ordinary mail.
		//
		// A decrypt FAILURE also leaves an empty body, and that half of the
		// original reasoning still holds: it may be transient, so it stays
		// uncached and retryable. Hence the error must be empty too.
		classified := in.PGPEncrypted && in.PGPDecryptError == ""
		if in.Body != "" || classified {
			if in.Body != "" {
				// warmBody, not in.Body: a decrypted OpenPGP body is never
				// persisted. Assigning it here also clears any plaintext an
				// older build already wrote for this UID.
				updated.Body = warmBody(mailboxKey, in)
				updated.BodyMode = in.BodyMode
			}
			updated.PGPEncrypted = in.PGPEncrypted
			updated.PGPSigned = in.PGPSigned
			updated.PGPVerified = in.PGPVerified
			updated.PGPSignerFingerprint = in.PGPSignerFingerprint
			updated.PGPProtectedSubject = in.PGPProtectedSubject
			// The stamp travels with the verdict it describes. Without this the
			// existing-UID branch kept a zero version alongside a fresh verdict,
			// and dropStaleVerdicts then discarded both on the very next load —
			// which is the production ordering, since the poller creates the
			// entry before the API warms the verdict into it.
			updated.PGPVerdictSchemaVersion = in.PGPVerdictSchemaVersion
			updated.ContactKeyGen = in.ContactKeyGen
		}
```

Note `updated.Body` and `updated.BodyMode` stay inside the inner `in.Body != ""` check — a bodyless warm must not blank a body an earlier warm stored.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/mailcache/ -v
```

Expected: PASS, including the pre-existing suite.

- [ ] **Step 5: Prove the first test by deliberate break**

Temporarily revert `classified` to `false` in `store.go`, re-run, confirm `TestUpsertKeepsPGPFlags…` FAILS, then restore.

- [ ] **Step 6: Widen the matching guard in `server_inbox.go`**

At line ~504, replace:

```go
			for i, e := range result.New {
				if c, ok := contents[e.UID]; ok && c.Body != "" {
```

with:

```go
			for i, e := range result.New {
				// Same rule as mailcache.Upsert: a client-protected message is
				// classified correctly AND bodyless, so the body cannot be the
				// only sentinel. A failed decrypt stays uncached.
				c, ok := contents[e.UID]
				if ok && c.Body == "" && !(c.PGPEncrypted && c.PGPDecryptError == "") {
					ok = false
				}
				if ok {
```

and inside that block add the field the original omitted, so a cached entry can express a decrypt failure:

```go
					e.PGPDecryptError = c.PGPDecryptError
```

- [ ] **Step 7: Run the full server suite**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/... 2>&1 | tail -30
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
# Branch off main, which is synced with upstream. Do NOT stack this on whatever
# branch happens to be checked out.
git checkout main && git checkout -b fix/client-protected-pgp-flags
git add backend/internal/mailcache/store.go backend/internal/mailcache/store_test.go backend/internal/api/server_inbox.go
git commit -m "fix(mail): keep the PGP flags for bodyless client-protected messages

The flags were gated on a non-empty body in mailcache.Upsert and in the
inbox delta write-back. That reasoning holds for server-protected
accounts and inverts for client-protected ones, where a correct
classification always arrives with an empty body because the server
deliberately does not decrypt.

cache.Sync creates the entry from overviews with no PGP data, the
write-back that would correct it was skipped, and every poll after the
first reported the message as ordinary mail — so the phone rendered
'nothing to show' and never offered to decrypt.

A failed decrypt still stays uncached: it may be transient.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Signer keys carry their trust provenance

**Files:**
- Modify: `backend/internal/api/pgp_receive.go:210-213` (struct), `:340-362` (`boundSignerKeys`)
- Test: `backend/internal/api/pgp_receive_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: the `signerKeys` JSON array in both `GET /api/pgp/bootstrap` and `GET /api/mail/pgp-payload` gains `verified` (bool), `source` (string), `conflict` (bool). Task 5's `SignerBinding` consumes exactly these names.

**Background.** `contacts.Contact` already tracks `PGPKeySource` (`manual|qr|wkd|keyserver|autocrypt`), `PGPKeyVerified` ("user eyeballed the fingerprint / came via QR") and `PGPKeyFingerprint` (the TOFU pin, enforced by `keyMatchesPin`). `boundSignerKey` discards all three. Because most keys are Autocrypt-harvested, one flat "signature verified" badge would assert identity on evidence that supports only continuity; and a key that fails its pin is currently `continue`d, so a **changed key** reaches the client as "no key bound to this sender" — identical to an ordinary new correspondent.

- [ ] **Step 1: Write the failing tests**

Add to `backend/internal/api/pgp_receive_test.go`:

```go
// Most keys are Autocrypt-harvested. If the wire cannot distinguish them
// from a fingerprint-confirmed key, the client can only show one badge,
// and it would claim identity on evidence that shows only continuity.
func TestBoundSignerKeysCarriesProvenance(t *testing.T) {
	store := newTestContactsStore(t)
	mustUpsertContact(t, store, contacts.Contact{
		Emails:            []contacts.Field{{Value: "confirmed@example.com"}},
		PGPKey:            testPublicKeyArmored,
		PGPKeyFingerprint: testPublicKeyFingerprint,
		PGPKeySource:      "qr",
		PGPKeyVerified:    true,
	})
	mustUpsertContact(t, store, contacts.Contact{
		Emails:            []contacts.Field{{Value: "harvested@example.com"}},
		PGPKey:            testPublicKeyArmored,
		PGPKeyFingerprint: testPublicKeyFingerprint,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
		PGPKeyVerified:    false,
	})

	got := boundSignerKeys(store)

	byAddr := map[string]boundSignerKey{}
	for _, k := range got {
		byAddr[k.Addresses[0]] = k
	}
	if c := byAddr["confirmed@example.com"]; !c.Verified || c.Source != "qr" {
		t.Fatalf("confirmed key lost its provenance: %+v", c)
	}
	if h := byAddr["harvested@example.com"]; h.Verified || h.Source != contacts.PGPSourceAutocrypt {
		t.Fatalf("harvested key misreported: %+v", h)
	}
}

// A key that no longer matches its TOFU pin is the one alarm TOFU exists
// to raise. Dropping the contact made it arrive as "no key bound to this
// sender", which is what an ordinary new correspondent looks like.
func TestBoundSignerKeysMarksPinConflictInsteadOfDropping(t *testing.T) {
	store := newTestContactsStore(t)
	mustUpsertContact(t, store, contacts.Contact{
		Emails:            []contacts.Field{{Value: "rotated@example.com"}},
		PGPKey:            testPublicKeyArmored,
		PGPKeyFingerprint: "0000NOTTHEPINNEDFINGERPRINT0000",
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})

	got := boundSignerKeys(store)

	if len(got) != 1 {
		t.Fatalf("want the conflicted contact reported, got %d entries", len(got))
	}
	if !got[0].Conflict {
		t.Fatal("a pin mismatch was not marked as a conflict")
	}
	if got[0].PublicKey != "" {
		t.Fatal("a conflicted key must not ship key material; it can never be trusted to verify")
	}
}
```

> If `newTestContactsStore` / `mustUpsertContact` / `testPublicKeyArmored` / `testPublicKeyFingerprint` do not already exist in this package's tests, read `backend/internal/api/pgp_receive_test.go` and reuse whatever equivalents it has; do not invent a second fixture style.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run 'TestBoundSignerKeys' -v
```

Expected: FAIL to compile — `c.Verified undefined`.

- [ ] **Step 3: Extend the wire struct**

In `backend/internal/api/pgp_receive.go`, replace lines 210-213:

```go
// boundSignerKey is one address-bound contact key as the client sees it.
//
// Verified and Source exist because a flat "signature verified" would
// claim identity on evidence that often shows only continuity: most keys
// arrive by Autocrypt harvest, and TOFU guarantees "same key as last
// time", not "this is who they say they are". The client renders the two
// differently.
//
// Conflict reports a contact whose stored key no longer matches its TOFU
// pin. Such a contact used to be skipped, so a CHANGED key reached the
// client as "no key bound to this sender" — indistinguishable from an
// ordinary new correspondent, which is the one case TOFU must shout
// about. PublicKey is deliberately empty on a conflicted entry: it can
// never be trusted to verify anything, and shipping it invites a client
// to try.
//
// Nothing secret crosses the wire. This is the user's own address book
// describing itself, and the public key was already here.
type boundSignerKey struct {
	Addresses []string `json:"addresses"`
	PublicKey string   `json:"publicKey"`
	Verified  bool     `json:"verified,omitempty"`
	Source    string   `json:"source,omitempty"`
	Conflict  bool     `json:"conflict,omitempty"`
}
```

- [ ] **Step 4: Stop discarding provenance in `boundSignerKeys`**

Replace the body of `boundSignerKeys` (lines ~340-362):

```go
func boundSignerKeys(store *contacts.Store) []boundSignerKey {
	out := []boundSignerKey{}
	for _, c := range store.List() {
		if c.PGPKey == "" {
			continue
		}
		addresses := make([]string, 0, len(c.Emails))
		seen := map[string]bool{}
		for _, e := range c.Emails {
			addr := strings.ToLower(strings.TrimSpace(e.Value))
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			addresses = append(addresses, addr)
		}
		if len(addresses) == 0 {
			continue
		}
		// A pin mismatch is reported, not dropped — but without key
		// material, so no client can verify against it.
		if !keyMatchesPin(c) {
			out = append(out, boundSignerKey{Addresses: addresses, Conflict: true})
			continue
		}
		out = append(out, boundSignerKey{
			Addresses: addresses,
			PublicKey: c.PGPKey,
			Verified:  c.PGPKeyVerified,
			Source:    c.PGPKeySource,
		})
	}
	return out
}
```

`signerKeysForSender` is **not** changed: it feeds the server's own verification and must keep excluding pin-mismatched keys entirely.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run 'TestBoundSignerKeys' -v
```

Expected: PASS.

- [ ] **Step 6: Prove by deliberate break**

Temporarily set `Verified: false` unconditionally in the final append; confirm `TestBoundSignerKeysCarriesProvenance` FAILS; restore.

- [ ] **Step 7: Run the full server suite**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/... 2>&1 | tail -30
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/api/pgp_receive.go backend/internal/api/pgp_receive_test.go
git commit -m "feat(pgp): ship signer key provenance and pin conflicts to clients

boundSignerKey carried only {addresses, publicKey}, discarding
PGPKeyVerified and PGPKeySource, which the address book already tracks.
Most keys are Autocrypt-harvested, so a client could only render one
'signature verified' badge — asserting identity on evidence that shows
only continuity.

A contact whose key no longer matches its TOFU pin was skipped
entirely, so a CHANGED key arrived as 'no key bound to this sender',
identical to an ordinary new correspondent. It is now reported with
conflict:true and no key material.

signerKeysForSender is unchanged: the server's own verification must
keep excluding pin-mismatched keys outright.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

# Part 1 — kypost-android

### Task 3: `PgpDecryptor` — decrypt and report a raw signature verdict

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/TestPgpPrivateKey.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/PgpDecryptorTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```kotlin
  internal data class RawSignature(val present: Boolean, val valid: Boolean, val signerKeyId: Long)
  internal sealed class DecryptResult {
      data class Ok(val plaintext: ByteArray, val signature: RawSignature) : DecryptResult()
      data class Failed(val message: String) : DecryptResult()
  }
  internal object PgpDecryptor {
      fun decrypt(
          armoredPrivateKey: String,
          armoredMessage: String,
          signerPublicKeys: List<String>,
      ): DecryptResult
      fun verifyDetached(armoredPublicKey: String, body: ByteArray, armoredSignature: String): RawSignature
  }
  ```
  Task 5 (`SignerBinding`) consumes `RawSignature`. Task 8 consumes `DecryptResult`.

  **`signerPublicKeys` has no default, deliberately.** A one-pass signature can only be completed
  against the signer's public key, and this object never takes one from the message itself — a
  message that vouches for itself proves only that whoever wrote it owned a key. Task 8 passes the
  address-bound keys. If this parameter could be omitted, `valid` would silently stay false, and
  `signatureStateFor` maps *signed + bound key + not valid* to `INVALID` — rendering "this message's
  signature does not match the sender it claims to be from" for **every** legitimately signed
  message from a contact whose key the user actually holds. Requiring the argument makes that
  mistake a compile error rather than a false accusation.

- [ ] **Step 1: Generate the test fixture**

The existing `TestPgpKey.kt` holds a *public* key only. Decryption needs a private key and a real ciphertext, produced by an implementation independent of BouncyCastle — the same reasoning `TestPgpKey`'s KDoc gives.

```bash
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-generate-key 'PgpDecryptorTest <decrypt@example.invalid>' ed25519 cert never
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')
gpg --batch --passphrase '' --quick-add-key "$FPR" cv25519 encr never
gpg --armor --export-secret-keys "$FPR" > /tmp/priv.asc
printf 'Hello from a real OpenPGP message.\n' \
  | gpg --batch --yes --armor --encrypt --sign --recipient "$FPR" > /tmp/msg.asc
echo "FINGERPRINT: $FPR"; cat /tmp/priv.asc; cat /tmp/msg.asc
```

Create `app/src/test/java/com/urlxl/mail/pgp/TestPgpPrivateKey.kt` with the two blocks pasted in:

```kotlin
package com.urlxl.mail.pgp

/**
 * A disposable, passphrase-free ed25519/cv25519 pair and one message encrypted and signed to it,
 * both produced by `gpg` — deliberately a different OpenPGP implementation from the Bouncy Castle
 * code under test, for the reason [TestPgpKey] gives: a fixture generated by the implementation
 * being tested only proves the code agrees with itself.
 *
 * Never a real key. Regenerate with the commands in this task's plan step if it needs replacing.
 */
internal object TestPgpPrivateKey {
    const val FINGERPRINT = "<paste FPR>"

    /** Decrypts to exactly [EXPECTED_PLAINTEXT], signed by this same key. */
    const val EXPECTED_PLAINTEXT = "Hello from a real OpenPGP message.\n"

    val ARMORED_PRIVATE = """
        <paste /tmp/priv.asc verbatim>
    """.trimIndent()

    val ARMORED_MESSAGE = """
        <paste /tmp/msg.asc verbatim>
    """.trimIndent()
}
```

Then clean up: `rm -rf "$GNUPGHOME" /tmp/priv.asc /tmp/msg.asc`.

- [ ] **Step 2: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/PgpDecryptorTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * These run on the JVM against a gpg-produced vector. `isReturnDefaultValues = true` is project-wide,
 * so a decryptor that reached for an Android framework class would silently resolve to a stub and
 * these would pass against an implementation that does nothing — which is exactly how
 * `parseDeviceEnvelope` once returned null for every input under three passing tests. Hence
 * [PgpDecryptor] uses Bouncy Castle's lightweight `Bc*` operators and no Android imports at all.
 */
class PgpDecryptorTest {

    /** The signer keys the reader will pass in production. A secret key ring also exposes its
     *  public keys, so the fixture can verify its own signature — acceptable HERE because
     *  [SignerBinding] is what forbids self-verification in production: it only ever supplies keys
     *  the address book bound to the displayed sender. */
    private val signerKeys = listOf(TestPgpPrivateKey.ARMORED_PRIVATE)

    @Test
    fun decryptsAMessageEncryptedByGpg() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE,
            TestPgpPrivateKey.ARMORED_MESSAGE,
            signerKeys,
        )

        val ok = result as? DecryptResult.Ok
            ?: throw AssertionError("expected Ok, got $result")
        assertEquals(TestPgpPrivateKey.EXPECTED_PLAINTEXT, String(ok.plaintext, Charsets.UTF_8))
    }

    @Test
    fun reportsTheEmbeddedSignatureAsValid() {
        val ok = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE,
            TestPgpPrivateKey.ARMORED_MESSAGE,
            signerKeys,
        ) as DecryptResult.Ok

        assertTrue("signature should be present", ok.signature.present)
        assertTrue("signature should verify", ok.signature.valid)
    }

    @Test
    fun reportsAPresentSignatureAsUnverifiedWhenNoSignerKeyIsOffered() {
        // Not "no signature": the message IS signed, and we simply cannot check it. The caller
        // maps this through SignerBinding, which turns an unbound signer into SIGNER_UNKNOWN.
        val ok = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE,
            TestPgpPrivateKey.ARMORED_MESSAGE,
            emptyList(),
        ) as DecryptResult.Ok

        assertTrue("signature should still be reported as present", ok.signature.present)
        assertEquals(false, ok.signature.valid)
    }

    @Test
    fun failsClosedOnAMessageThatIsNotOpenPGP() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE, "not a pgp message", signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }

    @Test
    fun failsClosedWhenTheKeyCannotDecryptTheMessage() {
        // TestPgpKey is a different, unrelated pair — and a public key at that.
        val result = PgpDecryptor.decrypt(
            TestPgpKey.ARMORED, TestPgpPrivateKey.ARMORED_MESSAGE, signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpDecryptorTest"
```

Expected: FAIL — unresolved reference `PgpDecryptor`.

- [ ] **Step 4: Implement `PgpDecryptor`**

Create `app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

/** What the cryptography alone can say about a signature: nothing about *who* the sender is. */
internal data class RawSignature(
    val present: Boolean,
    val valid: Boolean,
    /** The signing key's id, so [SignerBinding] can match it against an address-bound key. */
    val signerKeyId: Long,
)

internal sealed class DecryptResult {
    data class Ok(val plaintext: ByteArray, val signature: RawSignature) : DecryptResult() {
        // Kotlin generates identity equals/hashCode for a ByteArray property, and a data class
        // silently promising structural equality it does not provide is a trap. Nothing compares
        // these, so both are explicitly unsupported rather than subtly wrong.
        override fun equals(other: Any?) = this === other
        override fun hashCode() = System.identityHashCode(this)
    }

    data class Failed(val message: String) : DecryptResult()
}

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
internal object PgpDecryptor {

    fun decrypt(
        armoredPrivateKey: String,
        armoredMessage: String,
        /** The public keys the address book binds to the displayed sender, from [SignerKey]. A
         *  one-pass signature cannot be completed without one, and the key travelling inside the
         *  signed message is deliberately never used: a message that vouches for itself proves
         *  only that whoever wrote it owned a key. Empty means "present but unverifiable". */
        signerPublicKeys: List<String>,
    ): DecryptResult = runCatching {
        val secretKeys = PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPrivateKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        )

        val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredMessage.byteInputStream(Charsets.UTF_8)),
        )
        var obj = factory.nextObject()
        val encryptedList = (obj as? PGPEncryptedDataList)
            ?: (factory.nextObject() as? PGPEncryptedDataList)
            ?: return DecryptResult.Failed("not an encrypted OpenPGP message")

        // Try every recipient packet: a message may be encrypted to several keys, only one of
        // which is ours, and the packet order is the sender's choice.
        var clear: InputStream? = null
        var encrypted: PGPPublicKeyEncryptedData? = null
        for (item in encryptedList.encryptedDataObjects) {
            val pked = item as? PGPPublicKeyEncryptedData ?: continue
            val secretKey = secretKeys.getSecretKey(pked.keyID) ?: continue
            // Empty passphrase: the armored key came out of the device envelope already
            // unwrapped. A key that still needs one is not a key this device can use.
            val privateKey = secretKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
            )
            clear = pked.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
            encrypted = pked
            break
        }
        if (clear == null || encrypted == null) {
            return DecryptResult.Failed("this message is not encrypted to a key on this device")
        }

        val (plaintext, signature) = readLiteral(clear, signerPublicKeys)

        // Integrity protection is not optional. An unprotected message is malleable, and
        // accepting one would let a tampered ciphertext render as an ordinary message.
        if (encrypted.isIntegrityProtected && !encrypted.verify()) {
            return DecryptResult.Failed("this message failed its integrity check")
        }

        DecryptResult.Ok(plaintext, signature)
    }.getOrElse { DecryptResult.Failed(it.message ?: "could not decrypt this message") }

    /** Verifies an RFC 3156 detached signature over an already-readable body. */
    fun verifyDetached(
        armoredPublicKey: String,
        body: ByteArray,
        armoredSignature: String,
    ): RawSignature = runCatching {
        val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredSignature.byteInputStream(Charsets.UTF_8)),
        )
        val list = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature(present = false, valid = false, signerKeyId = 0L)
        val signature = list[0]

        val rings = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        )
        val key = rings.getPublicKey(signature.keyID)
            ?: return RawSignature(present = true, valid = false, signerKeyId = signature.keyID)

        signature.init(BcPGPContentVerifierBuilderProvider(), key)
        signature.update(body)
        RawSignature(present = true, valid = signature.verify(), signerKeyId = signature.keyID)
    }.getOrElse { RawSignature(present = true, valid = false, signerKeyId = 0L) }

    /**
     * Walks the decrypted stream to its literal data, checking any one-pass signature on the way.
     *
     * The signature is verified over the literal data as it is read, which is why this cannot be
     * split into "get the bytes" and "check the signature" — the one-pass form requires both in a
     * single traversal.
     */
    private fun readLiteral(
        clear: InputStream,
        signerPublicKeys: List<String>,
    ): Pair<ByteArray, RawSignature> {
        var factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(clear)
        var onePass: org.bouncycastle.openpgp.PGPOnePassSignature? = null
        var obj = factory.nextObject()

        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(obj.dataStream)
                }
                is PGPOnePassSignatureList -> {
                    onePass = obj[0]
                }
                is PGPLiteralData -> {
                    val out = ByteArrayOutputStream()
                    obj.inputStream.copyTo(out)
                    val bytes = out.toByteArray()
                    return bytes to verifyOnePass(onePass, bytes, factory, signerPublicKeys)
                }
            }
            obj = factory.nextObject()
        }
        return ByteArray(0) to RawSignature(present = false, valid = false, signerKeyId = 0L)
    }

    /**
     * Completes a one-pass signature against the literal bytes just read.
     *
     * The signer's public key travels inside the signed message often enough to be tempting, and it
     * is deliberately NOT used to self-verify: a message that vouches for itself proves only that
     * whoever wrote it owned a key. Only [signerPublicKeys] — which the address book bound to the
     * displayed sender — can produce `valid = true`.
     *
     * `present = true, valid = false` with no offered key is **not** an accusation. It means "signed,
     * unverifiable here", and [signatureStateFor] is what decides whether that reads as
     * SIGNER_UNKNOWN (no key bound) or INVALID (a key is bound and it did not match).
     */
    private fun verifyOnePass(
        onePass: org.bouncycastle.openpgp.PGPOnePassSignature?,
        body: ByteArray,
        factory: org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory,
        signerPublicKeys: List<String>,
    ): RawSignature {
        if (onePass == null) return RawSignature(present = false, valid = false, signerKeyId = 0L)
        val tail = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature(present = true, valid = false, signerKeyId = onePass.keyID)

        val key = signerPublicKeys.asSequence()
            .mapNotNull { armored ->
                runCatching {
                    PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                        BcKeyFingerprintCalculator(),
                    ).getPublicKey(onePass.keyID)
                }.getOrNull()
            }
            .firstOrNull()
            ?: return RawSignature(present = true, valid = false, signerKeyId = onePass.keyID)

        val valid = runCatching {
            onePass.init(BcPGPContentVerifierBuilderProvider(), key)
            onePass.update(body)
            onePass.verify(tail[0])
        }.getOrDefault(false)

        return RawSignature(present = true, valid = valid, signerKeyId = onePass.keyID)
    }
}
```

> A `PGPSecretKeyRingCollection`'s armored form also parses as a `PGPPublicKeyRingCollection`, which is why the test can pass `TestPgpPrivateKey.ARMORED_PRIVATE` as a signer key. In production Task 8 passes only `SignerKey.publicKey` values.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpDecryptorTest"
```

Expected: PASS, 5 tests.

- [ ] **Step 6: Prove by deliberate break**

Change `decryptsAMessageEncryptedByGpg`'s expected plaintext to `"WRONG"`. Re-run. Confirm FAIL with a real byte comparison in the message (not a null-vs-null pass). Restore.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/PgpDecryptor.kt \
        app/src/test/java/com/urlxl/mail/pgp/PgpDecryptorTest.kt \
        app/src/test/java/com/urlxl/mail/pgp/TestPgpPrivateKey.kt
git commit -m "feat(pgp): decrypt OpenPGP messages on the device

Bouncy Castle's lightweight Bc* operators, not Jce*: Android ships a
stripped BC provider that collides with the full one, so the Jce* path
behaves differently on a device than in a JVM test. Bc* uses no JCE
provider at all, which is what makes the unit tests evidence under the
project-wide isReturnDefaultValues.

Vector generated by gpg, not by Bouncy Castle, for the reason TestPgpKey
already gives.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: `PgpMimeReader` — decrypted bytes to a renderable body

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/PgpMimeReader.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/PgpMimeReaderTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces:
  ```kotlin
  internal data class DecryptedBody(val html: String?, val plain: String?, val protectedSubject: String?)
  internal object PgpMimeReader { fun read(mime: ByteArray): DecryptedBody? }
  ```
  Task 8 consumes `DecryptedBody`.

**Background.** `angus.mail` (`org.eclipse.angus:jakarta.mail:2.0.4`) is declared in `libs.versions.toml` and imported by **nothing** in main source. This is its first use in the app: on the classpath, but unproven.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/PgpMimeReaderTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PgpMimeReaderTest {

    private fun read(mime: String) = PgpMimeReader.read(mime.toByteArray(Charsets.UTF_8))

    @Test
    fun readsAPlainTextOnlyMessage() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8

            Just text.
            """.trimIndent(),
        )

        assertEquals("Just text.", body?.plain?.trim())
        assertNull(body?.html)
    }

    @Test
    fun prefersHtmlFromMultipartAlternative() {
        val body = read(
            """
            Content-Type: multipart/alternative; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            fallback text
            --b1
            Content-Type: text/html; charset=utf-8

            <p>rich text</p>
            --b1--
            """.trimIndent(),
        )

        assertTrue("expected the html part", body?.html?.contains("rich text") == true)
        assertTrue("expected the plain part kept too", body?.plain?.contains("fallback text") == true)
    }

    @Test
    fun recoversAProtectedSubject() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8
            Subject: The real subject

            body
            """.trimIndent(),
        )

        assertEquals("The real subject", body?.protectedSubject)
    }

    @Test
    fun returnsNullForBytesThatAreNotMime() {
        // Fails closed: the caller shows "could not decrypt" rather than rendering garbage
        // into a WebView.
        assertNull(PgpMimeReader.read(byteArrayOf(0x00, 0x01, 0x02)))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpMimeReaderTest"
```

Expected: FAIL — unresolved reference `PgpMimeReader`.

- [ ] **Step 3: Implement `PgpMimeReader`**

Create `app/src/main/java/com/urlxl/mail/pgp/PgpMimeReader.kt`:

```kotlin
package com.urlxl.mail.pgp

import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.util.Properties

/**
 * The readable parts of a decrypted PGP/MIME message.
 *
 * Both [html] and [plain] are kept rather than collapsing to one: the caller decides what to put in
 * the WebView, and a message with only a plain part must not render as an empty page.
 */
internal data class DecryptedBody(
    val html: String?,
    val plain: String?,
    /** The real subject from the encrypted part's protected headers, when the sender used them.
     *  The outer envelope subject is a placeholder for KyPost-to-KyPost mail. */
    val protectedSubject: String?,
)

/**
 * Parses decrypted PGP/MIME bytes with `angus.mail`, with **no Android imports**.
 *
 * Note this is `angus.mail`'s first use in this app — it has been a declared dependency, imported by
 * nothing, so "already on the classpath" was never the same as "known to work here".
 *
 * Returns null rather than throwing on anything unparseable. The caller renders an exit-table row;
 * putting unparsed bytes into a WebView is not a degradation this accepts.
 */
internal object PgpMimeReader {

    fun read(mime: ByteArray): DecryptedBody? = runCatching {
        val session = Session.getInstance(Properties())
        val message = MimeMessage(session, ByteArrayInputStream(mime))

        var html: String? = null
        var plain: String? = null

        fun walk(content: Any?) {
            when (content) {
                is String -> Unit
                is MimeMultipart -> {
                    for (i in 0 until content.count) {
                        val part = content.getBodyPart(i)
                        val body = runCatching { part.content }.getOrNull()
                        when {
                            part.isMimeType("text/html") -> html = html ?: body as? String
                            part.isMimeType("text/plain") -> plain = plain ?: body as? String
                            body is MimeMultipart -> walk(body)
                        }
                    }
                }
            }
        }

        val content = message.content
        when {
            message.isMimeType("text/html") -> html = content as? String
            message.isMimeType("text/plain") -> plain = content as? String
            else -> walk(content)
        }

        if (html == null && plain == null) return null
        DecryptedBody(
            html = html,
            plain = plain,
            protectedSubject = message.subject?.takeIf { it.isNotBlank() },
        )
    }.getOrNull()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpMimeReaderTest"
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Prove by deliberate break**

Change `readsAPlainTextOnlyMessage` to expect `"Something else."`. Confirm FAIL shows the real parsed string, proving `angus.mail` actually ran rather than returning a stub. Restore.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/PgpMimeReader.kt \
        app/src/test/java/com/urlxl/mail/pgp/PgpMimeReaderTest.kt
git commit -m "feat(pgp): parse decrypted PGP/MIME into a renderable body

First actual use of angus.mail in this app — it has been a declared
dependency imported by nothing, so being on the classpath was never the
same as being known to work.

Unparseable bytes return null rather than throwing: the caller shows an
error instead of putting unparsed bytes into a WebView.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Six signature states, bound to the sender

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt`
- Modify: `app/src/main/java/com/urlxl/mail/pgp/PgpMessageState.kt:96-137`
- Modify: `app/src/main/java/com/urlxl/mail/EmailAdapter.kt:34`
- Modify: `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt:412-416`
- Modify: `app/src/main/res/values/strings.xml:81`
- Test: `app/src/test/java/com/urlxl/mail/pgp/SignerBindingTest.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/PgpMessageStateTest.kt` (extend)

**Interfaces:**
- Consumes: `RawSignature` (Task 3); the `signerKeys` wire fields `addresses`/`publicKey`/`verified`/`source`/`conflict` (Task 2).
- Produces:
  ```kotlin
  internal data class SignerKey(
      val addresses: List<String>, val publicKey: String,
      val verified: Boolean, val source: String, val conflict: Boolean,
  )
  internal fun signatureStateFor(
      signature: RawSignature, senderAddress: String, signerKeys: List<SignerKey>,
  ): PgpSignatureState
  enum class PgpSignatureState { NONE, VERIFIED_CONFIRMED, VERIFIED_SEEN_BEFORE, SIGNER_UNKNOWN, KEY_CHANGED, INVALID }
  ```
  Tasks 6 and 8 consume `SignerKey`. Task 10 renders `PgpSignatureState`.

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/SignerBindingTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The two assertions that matter most are [autocryptKeyIsNeverConfirmed] and
 * [changedKeyIsNeverJustUnknown]. Both are cases where the wrong answer is *plausible* and quiet:
 * one over-claims identity on a key nobody checked, the other displays an active-attack signal as
 * the most routine message in the app.
 */
class SignerBindingTest {

    private fun sig(valid: Boolean = true) =
        RawSignature(present = true, valid = valid, signerKeyId = 1L)

    private fun key(
        address: String = "bob@example.com",
        verified: Boolean = false,
        source: String = "autocrypt",
        conflict: Boolean = false,
        publicKey: String = TestPgpKey.ARMORED,
    ) = SignerKey(listOf(address), publicKey, verified, source, conflict)

    @Test
    fun unsignedIsNone() {
        val state = signatureStateFor(
            RawSignature(present = false, valid = false, signerKeyId = 0L),
            "bob@example.com",
            listOf(key()),
        )
        assertEquals(PgpSignatureState.NONE, state)
    }

    @Test
    fun confirmedKeyBoundToTheSenderIsConfirmed() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(verified = true, source = "qr")))
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun autocryptKeyIsNeverConfirmed() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(source = "autocrypt")))
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    @Test
    fun noKeyBoundToTheSenderIsUnknown() {
        val state = signatureStateFor(sig(), "carol@example.com", listOf(key(address = "bob@example.com")))
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun changedKeyIsNeverJustUnknown() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(conflict = true, publicKey = "")))
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aBadSignatureAgainstABoundKeyIsInvalid() {
        val state = signatureStateFor(sig(valid = false), "bob@example.com", listOf(key()))
        assertEquals(PgpSignatureState.INVALID, state)
    }

    @Test
    fun senderMatchingIgnoresDisplayNameAndCase() {
        // The relay sends the RAW From header. Comparing that against a bare address matched
        // nothing for any correspondent with a display name, while a bare `From: bob@…` — the
        // form an attacker always chooses — went on matching. A binding that only fires for the
        // attacker is worse than no binding.
        val state = signatureStateFor(
            sig(), "Bob Example <BOB@Example.com>", listOf(key(verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun aConflictOutranksAnOtherwiseGoodKeyForTheSameSender() {
        val state = signatureStateFor(
            sig(),
            "bob@example.com",
            listOf(key(verified = true, source = "manual"), key(conflict = true, publicKey = "")),
        )
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }
}
```

Add to `app/src/test/java/com/urlxl/mail/pgp/PgpMessageStateTest.kt`:

```kotlin
    @Test
    fun serverVerifiedNeverClaimsTheUserConfirmedTheKey() {
        // The relay's two booleans cannot tell a fingerprint-confirmed key from an
        // Autocrypt-harvested one, so the mapping takes the weaker claim. Promoting this to
        // VERIFIED_CONFIRMED would reintroduce the exact over-claim Part 0.2 removed.
        assertEquals(
            PgpSignatureState.VERIFIED_SEEN_BEFORE,
            pgpSignatureStateOf(pgpSigned = true, pgpVerified = true),
        )
    }

    @Test
    fun aChangedKeyMarksTheRow() {
        assertEquals("⚠", pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.KEY_CHANGED))
    }

    @Test
    fun anUnknownSignerDoesNotMarkTheRow() {
        // It is the ordinary state for anyone not yet in the address book. A glyph on most rows
        // carries nothing the user can act on — the same reason DECRYPTED_BY_SERVER is unmarked.
        assertNull(pgpRowMarker(PgpMessageState.NONE, PgpSignatureState.SIGNER_UNKNOWN))
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.SignerBindingTest" --tests "com.urlxl.mail.pgp.PgpMessageStateTest"
```

Expected: FAIL — unresolved references `signatureStateFor`, `SignerKey`, `VERIFIED_CONFIRMED`.

- [ ] **Step 3: Expand `PgpSignatureState`**

In `app/src/main/java/com/urlxl/mail/pgp/PgpMessageState.kt`, replace the enum (lines 96-105) and `pgpSignatureStateOf` (107-111):

```kotlin
enum class PgpSignatureState {
    /** Not signed, or no opinion was expressed. Nothing to say. */
    NONE,

    /** Signed by a key bound to the sender, and the user confirmed that key out of band — by
     *  eyeballing the fingerprint or scanning a QR code. The only state that claims identity. */
    VERIFIED_CONFIRMED,

    /**
     * Signed by a key bound to the sender that still matches its TOFU pin, but which nobody ever
     * confirmed. This claims **continuity**, not identity: the same key as last time.
     *
     * Distinct from [VERIFIED_CONFIRMED] because most keys arrive by Autocrypt harvest, so one flat
     * "verified" badge would assert the stronger property on the weaker evidence for nearly every
     * message — and a badge that over-claims on the common case is one users learn to ignore.
     */
    VERIFIED_SEEN_BEFORE,

    /** Signed, but no key we hold is bound to this sender. Not an accusation: the ordinary state
     *  for a correspondent who is not in the address book yet. */
    SIGNER_UNKNOWN,

    /**
     * A key IS bound to this sender and it no longer matches its TOFU pin.
     *
     * Under trust-on-first-use this is the one alarm worth raising. It used to be indistinguishable
     * from [SIGNER_UNKNOWN], because the server dropped a pin-mismatched contact entirely — so an
     * active key substitution displayed as the most routine message in the app.
     */
    KEY_CHANGED,

    /** Signed, and it does **not** verify against the key bound to the sender. */
    INVALID,
}

/**
 * The relay's verdict, for accounts whose key the **server** holds.
 *
 * Two booleans cannot express six states, and they cannot distinguish a fingerprint-confirmed key
 * from an Autocrypt-harvested one, so `pgpVerified` maps to the weaker of the two positive claims.
 * [PgpSignatureState.VERIFIED_CONFIRMED], [PgpSignatureState.SIGNER_UNKNOWN] and
 * [PgpSignatureState.KEY_CHANGED] are reachable only through [signatureStateFor], from a local
 * decrypt against a locally-held key.
 */
fun pgpSignatureStateOf(pgpSigned: Boolean, pgpVerified: Boolean): PgpSignatureState = when {
    !pgpSigned -> PgpSignatureState.NONE
    pgpVerified -> PgpSignatureState.VERIFIED_SEEN_BEFORE
    else -> PgpSignatureState.INVALID
}
```

And update `pgpRowMarker` (lines 121-129):

```kotlin
fun pgpRowMarker(
    state: PgpMessageState,
    /** A failed signature or a changed key outranks every readability marker: the row is
     *  readable, and that is exactly what makes an unflagged impersonation dangerous.
     *  SIGNER_UNKNOWN deliberately does not mark — see [PgpSignatureState.SIGNER_UNKNOWN]. */
    signature: PgpSignatureState = PgpSignatureState.NONE,
): String? = when (signature) {
    PgpSignatureState.INVALID, PgpSignatureState.KEY_CHANGED -> "⚠"
    else -> pgpReadabilityMarker(state)
}
```

- [ ] **Step 4: Implement `SignerBinding`**

Create `app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * One address-bound contact key as the server ships it.
 *
 * [addresses] is the binding the **server's** address book computed. The client must not re-derive
 * it from the key's own User IDs: one key can self-assert two User IDs, so a binding taken from the
 * key material is forgeable, and re-deriving it with a second parser is how a client can end up
 * vouching for a key the server's own binding rejects.
 *
 * [conflict] means the stored key no longer matches its TOFU pin. Such an entry carries no
 * [publicKey] and is never offered to a signature check — it exists so the reader can say the key
 * changed instead of silently reporting an unknown signer.
 */
internal data class SignerKey(
    val addresses: List<String>,
    val publicKey: String,
    val verified: Boolean,
    val source: String,
    val conflict: Boolean,
)

/**
 * Extracts the bare addr-spec from a From header value.
 *
 * The relay sends the RAW header, which renders as `Name <addr>` whenever a display name is
 * present. Comparing that against a bare address matched nothing, so the binding silently returned
 * no keys for every correspondent who has a display name — while a bare `From: bob@example.com`,
 * the form an attacker controls and therefore always chooses, went on matching. A binding that only
 * ever fires for the attacker is worse than no binding. This mirrors the server's `senderAddrSpec`.
 */
internal fun senderAddrSpec(sender: String): String {
    val raw = sender.trim()
    if (raw.isEmpty()) return ""
    val open = raw.lastIndexOf('<')
    if (open >= 0) {
        val close = raw.indexOf('>', open + 1)
        if (close >= 0) return raw.substring(open + 1, close).trim().lowercase()
    }
    return raw.lowercase()
}

/**
 * The signature verdict for a message being displayed as being from [senderAddress].
 *
 * A signature is accepted only from a key the address book binds to that sender. The signing key's
 * own claim about who it belongs to is never consulted.
 */
internal fun signatureStateFor(
    signature: RawSignature,
    senderAddress: String,
    signerKeys: List<SignerKey>,
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE

    val address = senderAddrSpec(senderAddress)
    if (address.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    val bound = signerKeys.filter { key -> key.addresses.any { it.trim().lowercase() == address } }
    if (bound.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN

    // A conflict outranks a good key for the same sender. Two entries for one address means one of
    // them is a key that changed, and reporting the survivor as verified would hide precisely the
    // event worth reporting.
    if (bound.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    if (!signature.valid) return PgpSignatureState.INVALID

    return if (bound.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
```

- [ ] **Step 5: Update the two `VERIFIED` call sites and the string**

`EmailDetailActivity.kt:412-416` — replace the `when` arms:

```kotlin
        val signatureNotice = when (pgpSignatureState) {
            PgpSignatureState.INVALID -> getString(R.string.email_pgp_signature_invalid)
            PgpSignatureState.KEY_CHANGED -> getString(R.string.email_pgp_signature_key_changed)
            PgpSignatureState.VERIFIED_CONFIRMED -> getString(R.string.email_pgp_signature_confirmed)
            PgpSignatureState.VERIFIED_SEEN_BEFORE -> getString(R.string.email_pgp_signature_seen_before)
            PgpSignatureState.SIGNER_UNKNOWN -> getString(R.string.email_pgp_signature_signer_unknown)
            PgpSignatureState.NONE -> null
        }
```

`strings.xml` — replace line 81 and add four:

```xml
    <string name="email_pgp_signature_confirmed">Signature verified against a key you confirmed for this sender.</string>
    <string name="email_pgp_signature_seen_before">Signature matches the key we have always seen from this sender. You have not confirmed that key, so this shows the message is consistent — not who sent it.</string>
    <string name="email_pgp_signature_signer_unknown">This message is signed, but you hold no key for this sender, so the signature can\'t be checked.</string>
    <string name="email_pgp_signature_key_changed">This sender\'s key has changed since you last heard from them. That can be an ordinary key rotation or an impersonation attempt — confirm the new fingerprint before trusting this message.</string>
```

Check `EmailAdapter.kt:34` compiles unchanged — it calls `pgpSignatureStateOf` and passes the result to `pgpRowMarker`, both of which keep their signatures. If it names `PgpSignatureState.VERIFIED` anywhere, update it.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.SignerBindingTest" --tests "com.urlxl.mail.pgp.PgpMessageStateTest" --tests "com.urlxl.mail.pgp.RendersNothingTest"
```

Expected: PASS.

- [ ] **Step 7: Prove by deliberate break**

In `signatureStateFor`, temporarily change the final `bound.any { it.verified }` to `true`. Confirm `autocryptKeyIsNeverConfirmed` FAILS. Restore.

- [ ] **Step 8: Full unit suite and commit**

```bash
./gradlew :app:testDebugUnitTest
git add app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt \
        app/src/main/java/com/urlxl/mail/pgp/PgpMessageState.kt \
        app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt \
        app/src/main/res/values/strings.xml \
        app/src/test/java/com/urlxl/mail/pgp/SignerBindingTest.kt \
        app/src/test/java/com/urlxl/mail/pgp/PgpMessageStateTest.kt
git commit -m "feat(pgp): distinguish a confirmed key from a key we have merely seen

PgpSignatureState had one VERIFIED, which claimed 'this really is from
the sender it names'. Most keys arrive by Autocrypt harvest, where TOFU
guarantees continuity and not identity, so that badge over-claimed on
nearly every message.

Six states now. Only VERIFIED_CONFIRMED claims identity, and it needs a
key the user checked out of band. KEY_CHANGED exists because a key that
fails its TOFU pin used to be indistinguishable from a correspondent who
simply is not in the address book — displaying the one alarm TOFU exists
to raise as the most routine message in the app.

The relay's two booleans map to VERIFIED_SEEN_BEFORE, never
VERIFIED_CONFIRMED: they cannot tell the two apart.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: `PgpPayloadClient` — fetch one message's ciphertext

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/PgpPayloadClient.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/PgpPayloadClientTest.kt`

**Interfaces:**
- Consumes: `SignerKey` (Task 5).
- Produces:
  ```kotlin
  internal sealed class PgpPayloadResult {
      data class Success(val encryptedPayload: String, val signaturePayload: String,
                         val body: String, val signerKeys: List<SignerKey>) : PgpPayloadResult()
      object NotClientProtected : PgpPayloadResult()   // 409
      object TooLarge : PgpPayloadResult()             // 413
      object NoPayload : PgpPayloadResult()            // 404
      data class Failed(val message: String) : PgpPayloadResult()
  }
  internal class PgpPayloadClient(callFactory: Call.Factory = pairingHttpClient()) {
      suspend fun fetch(serverUrl: String, deviceId: String, deviceSecret: String,
                        mailbox: String, messageId: String): PgpPayloadResult
  }
  ```

- [ ] **Step 1: Read the two patterns this must follow**

Read `app/src/main/java/com/urlxl/mail/pgp/PgpBootstrapClient.kt` and `app/src/test/java/com/urlxl/mail/pgp/PgpBootstrapClientTest.kt` in full. Match their construction (`pairingHttpClient`, `pairingAuthHeaders`, `pairingEndpoint`, `executeSync`, `withContext(Dispatchers.IO)`) and their fake-`Call.Factory` test style. Do not introduce a different HTTP or test idiom.

- [ ] **Step 2: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/PgpPayloadClientTest.kt`, following `PgpBootstrapClientTest`'s fake-call construction exactly:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PgpPayloadClientTest {

    private fun fetchWith(code: Int, body: String): PgpPayloadResult = runBlocking {
        // Build the fake Call.Factory the same way PgpBootstrapClientTest does.
        PgpPayloadClient(callFactory = fakeCallFactory(code, body))
            .fetch("https://relay.example", "dev-1", "secret", "INBOX", "42")
    }

    @Test
    fun parsesAPayloadWithItsSignerKeys() {
        val result = fetchWith(
            200,
            """
            {"messageId":42,"mailbox":"INBOX","encryptedPayload":"-----BEGIN PGP MESSAGE-----",
             "signaturePayload":"","body":"",
             "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"KEY",
                            "verified":true,"source":"qr"}]}
            """.trimIndent(),
        )

        val ok = result as? PgpPayloadResult.Success
            ?: throw AssertionError("expected Success, got $result")
        assertEquals("-----BEGIN PGP MESSAGE-----", ok.encryptedPayload)
        assertEquals(1, ok.signerKeys.size)
        assertTrue(ok.signerKeys[0].verified)
        assertEquals("qr", ok.signerKeys[0].source)
    }

    @Test
    fun absentProvenanceFieldsDefaultToTheWeakerClaim() {
        // omitempty: an older server sends neither field. Defaulting verified to false is the safe
        // direction — it degrades a badge, where the opposite would invent a confirmation.
        val result = fetchWith(
            200,
            """{"encryptedPayload":"X","signaturePayload":"","body":"",
                "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"KEY"}]}""",
        )

        val ok = result as PgpPayloadResult.Success
        assertEquals(false, ok.signerKeys[0].verified)
        assertEquals(false, ok.signerKeys[0].conflict)
    }

    @Test
    fun readsAConflictMarker() {
        val result = fetchWith(
            200,
            """{"encryptedPayload":"X","signaturePayload":"","body":"",
                "signerKeys":[{"addresses":["bob@example.com"],"publicKey":"","conflict":true}]}""",
        )

        assertTrue((result as PgpPayloadResult.Success).signerKeys[0].conflict)
    }

    @Test
    fun mapsTheThreeStatusCodesThatMeanSomethingSpecific() {
        assertTrue(fetchWith(409, "{}") is PgpPayloadResult.NotClientProtected)
        assertTrue(fetchWith(413, "{}") is PgpPayloadResult.TooLarge)
        assertTrue(fetchWith(404, "{}") is PgpPayloadResult.NoPayload)
    }

    @Test
    fun anyOtherErrorIsAPlainFailure() {
        assertTrue(fetchWith(500, "{}") is PgpPayloadResult.Failed)
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpPayloadClientTest"
```

Expected: FAIL — unresolved reference `PgpPayloadClient`.

- [ ] **Step 4: Implement `PgpPayloadClient`**

Create `app/src/main/java/com/urlxl/mail/pgp/PgpPayloadClient.kt`, mirroring `PgpBootstrapClient`:

```kotlin
package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import com.urlxl.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

/**
 * The outcome of asking the relay for one message's OpenPGP payload.
 *
 * The three specific status codes are distinct cases rather than one [Failed], because each gets a
 * different exit-table row and a different sentence to the user. Collapsing them would tell someone
 * whose message is simply too large that the server could not be reached.
 */
internal sealed class PgpPayloadResult {
    data class Success(
        val encryptedPayload: String,
        val signaturePayload: String,
        /** The readable body of a signed-but-not-encrypted message, which the client needs
         *  alongside a detached signature in order to verify it. Empty when encrypted. */
        val body: String,
        val signerKeys: List<SignerKey>,
    ) : PgpPayloadResult()

    /** 409 — this account's key is not client-protected. A bug if it is ever seen here. */
    object NotClientProtected : PgpPayloadResult()

    /** 413 — larger than the server will hold in memory. */
    object TooLarge : PgpPayloadResult()

    /** 404 — no message, or it carries no OpenPGP payload. */
    object NoPayload : PgpPayloadResult()

    data class Failed(val message: String) : PgpPayloadResult()
}

@Serializable
private data class SignerKeyDto(
    val addresses: List<String> = emptyList(),
    val publicKey: String = "",
    // Both are `omitempty` server-side. The Kotlin defaults ARE the contract for an older server,
    // and false is the safe direction for each: it weakens a claim rather than inventing one.
    val verified: Boolean = false,
    val source: String = "",
    val conflict: Boolean = false,
)

@Serializable
private data class PgpPayloadDto(
    val encryptedPayload: String = "",
    val signaturePayload: String = "",
    val body: String = "",
    val signerKeys: List<SignerKeyDto> = emptyList(),
)

private val JSON = Json { ignoreUnknownKeys = true }

/**
 * `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`.
 *
 * Built on the pinned pairing call factory by every real caller, like every other credentialed
 * request in this app — the default here exists for tests.
 */
internal class PgpPayloadClient(private val callFactory: Call.Factory = pairingHttpClient()) {

    suspend fun fetch(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        mailbox: String,
        messageId: String,
    ): PgpPayloadResult = withContext(Dispatchers.IO) {
        runCatching {
            val url = pairingEndpoint(serverUrl, "/api/mail/pgp-payload").toHttpUrl()
                .newBuilder()
                .addQueryParameter("mailbox", mailbox)
                .addQueryParameter("messageId", messageId)
                .build()
            val request = Request.Builder()
                .url(url)
                .headers(pairingAuthHeaders(deviceId, deviceSecret))
                .get()
                .build()

            callFactory.newCall(request).executeSync().use { response ->
                when (response.code) {
                    409 -> return@use PgpPayloadResult.NotClientProtected
                    413 -> return@use PgpPayloadResult.TooLarge
                    404 -> return@use PgpPayloadResult.NoPayload
                }
                if (!response.isSuccessful) {
                    return@use PgpPayloadResult.Failed("server returned ${response.code}")
                }
                val dto = JSON.decodeFromString<PgpPayloadDto>(response.body?.string().orEmpty())
                PgpPayloadResult.Success(
                    encryptedPayload = dto.encryptedPayload,
                    signaturePayload = dto.signaturePayload,
                    body = dto.body,
                    signerKeys = dto.signerKeys.map {
                        SignerKey(it.addresses, it.publicKey, it.verified, it.source, it.conflict)
                    },
                )
            }
        }.getOrElse { PgpPayloadResult.Failed(it.message ?: "could not reach the server") }
    }
}
```

> Import `okhttp3.HttpUrl.Companion.toHttpUrl`. If `pairingEndpoint` already returns an `HttpUrl` in this codebase, drop the `.toHttpUrl()` — check the signature before assuming.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.PgpPayloadClientTest"
```

Expected: PASS, 5 tests.

- [ ] **Step 6: Prove by deliberate break**

Change the `verified` DTO default to `true`. Confirm `absentProvenanceFieldsDefaultToTheWeakerClaim` FAILS. Restore.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/PgpPayloadClient.kt \
        app/src/test/java/com/urlxl/mail/pgp/PgpPayloadClientTest.kt
git commit -m "feat(pgp): fetch one message's OpenPGP payload from the relay

409, 413 and 404 stay distinct from a generic failure: each is a
different exit-table row, and collapsing them would tell someone whose
message is merely too large that the server could not be reached.

Absent provenance fields default to the weaker claim — an older server
degrades a badge rather than inventing a confirmation.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: `VaultOpener` — the biometric unseal port

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/VaultOpener.kt`
- Create: `app/src/main/java/com/urlxl/mail/pgp/VaultOpenerAndroid.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/VaultOpenerContractTest.kt`

**Interfaces:**
- Consumes: `EnrollmentVault` (`stored()`, `openCipher(iv)`), `EnrollmentSession.put`.
- Produces:
  ```kotlin
  internal sealed class OpenOutcome {
      object Opened : OpenOutcome()
      object Cancelled : OpenOutcome()
      object NotEnrolled : OpenOutcome()
      object NoSecureLockScreen : OpenOutcome()
      data class Failed(val message: String) : OpenOutcome()
  }
  internal interface VaultOpener { suspend fun open(): OpenOutcome }
  internal class AndroidVaultOpener(activity: FragmentActivity) : VaultOpener
  ```
  Task 8 consumes both.

- [ ] **Step 1: Read the mirror**

Read `EnrollmentPorts.kt` (the `VaultSealer` declaration and `SealOutcome`) and the `VaultSealer` implementation in `EnrollmentPortsAndroid.kt` / `DeviceEnrollmentActivity.kt`. `AndroidVaultOpener` is that code run in reverse — reuse its `BiometricPrompt` construction, its `PromptInfo` authenticator set, and its cancellation handling rather than writing new ones.

- [ ] **Step 2: Write the failing test**

Create `app/src/test/java/com/urlxl/mail/pgp/VaultOpenerContractTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The port's contract, not the Keystore. `AndroidVaultOpener` needs hardware and is covered by the
 * instrumented suite; what a JVM test can pin is the property the whole design rests on: an
 * [OpenOutcome] never carries key material, so no key can travel back through the orchestrator.
 */
class VaultOpenerContractTest {

    @After fun cleanup() = EnrollmentSession.clear()

    private class FakeOpener(private val outcome: OpenOutcome, private val key: String? = null) : VaultOpener {
        override suspend fun open(): OpenOutcome {
            if (key != null) EnrollmentSession.put(key)
            return outcome
        }
    }

    @Test
    fun openingPutsTheKeyInTheSessionAndReturnsNoMaterial() {
        val opener = FakeOpener(OpenOutcome.Opened, "-----BEGIN PGP PRIVATE KEY BLOCK-----")

        val outcome = runBlocking { opener.open() }

        assertEquals(OpenOutcome.Opened, outcome)
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----", EnrollmentSession.peek())
    }

    @Test
    fun cancellingLeavesTheSessionEmpty() {
        val opener = FakeOpener(OpenOutcome.Cancelled)

        val outcome = runBlocking { opener.open() }

        assertEquals(OpenOutcome.Cancelled, outcome)
        assertNull(EnrollmentSession.peek())
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.VaultOpenerContractTest"
```

Expected: FAIL — unresolved reference `OpenOutcome`.

- [ ] **Step 4: Declare the port**

Create `app/src/main/java/com/urlxl/mail/pgp/VaultOpener.kt`:

```kotlin
package com.urlxl.mail.pgp

/**
 * The result of unsealing the device envelope.
 *
 * [Opened] carries **no key material**, deliberately. [VaultSealer]'s KDoc records the same rule for
 * the sealing direction — "the sealer owns the ciphertext end to end so that no key material passes
 * back through the state machine" — and the opener is its mirror: it writes the plaintext straight
 * into [EnrollmentSession] and tells the caller only that it worked.
 *
 * [Cancelled] is not a failure. The user dismissed the prompt, or the hosting Activity went away.
 * The reader returns to offering the Decrypt button and says nothing, exactly as the enrollment
 * ceremony treats its own `Cancelled`.
 */
internal sealed class OpenOutcome {
    object Opened : OpenOutcome()
    object Cancelled : OpenOutcome()

    /** No sealed envelope on this device: never enrolled, or torn down by a wipe, an unpair or
     *  Hostile Location Protection. */
    object NotEnrolled : OpenOutcome()

    object NoSecureLockScreen : OpenOutcome()

    /** The envelope exists and could not be opened — typically a Keystore key the OS invalidated,
     *  which needs a fresh enrollment rather than a retry. */
    data class Failed(val message: String) : OpenOutcome()
}

/**
 * The unseal, behind an interface because `BiometricPrompt` is Activity-bound and the orchestrator
 * must stay free of Android imports.
 *
 * This is the seam that makes "the user dismissed the prompt" a JVM test with a fake rather than an
 * instrumented one — the same reason [VaultSealer] exists.
 */
internal interface VaultOpener {
    /** On [OpenOutcome.Opened], and only then, the armored private key is in [EnrollmentSession]. */
    suspend fun open(): OpenOutcome
}
```

- [ ] **Step 5: Implement the Android side**

Create `app/src/main/java/com/urlxl/mail/pgp/VaultOpenerAndroid.kt`:

```kotlin
package com.urlxl.mail.pgp

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.urlxl.mail.R
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher

/**
 * Opens the device envelope through a `BiometricPrompt.CryptoObject`, so the Keystore key's
 * `setUserAuthenticationRequired(true)` is satisfied by the same authentication the user just
 * performed.
 *
 * **This is [EnrollmentSession]'s first writer.** Decision 6 of the enrollment ceremony left the
 * holder without one on purpose: filling a process-scoped holder with the account's private key for
 * zero readers is exposure bought for nothing. The reader now exists.
 *
 * The plaintext is written into the holder here rather than returned, so it never passes through
 * [EncryptedMessageReader].
 */
internal class AndroidVaultOpener(private val activity: FragmentActivity) : VaultOpener {

    override suspend fun open(): OpenOutcome {
        val vault = EnrollmentVault(activity)
        if (!vault.ensureKey()) return OpenOutcome.NoSecureLockScreen
        val (iv, ciphertext) = vault.stored() ?: return OpenOutcome.NotEnrolled
        val cipher = vault.openCipher(iv) ?: return OpenOutcome.Failed(
            activity.getString(R.string.email_pgp_unseal_failed),
        )

        return suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(
                activity,
                androidx.core.content.ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val opened = result.cryptoObject?.cipher
                        if (opened == null) {
                            cont.resume(OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed)))
                            return
                        }
                        val outcome = runCatching {
                            val plaintext = opened.doFinal(ciphertext)
                            EnrollmentSession.put(String(plaintext, Charsets.UTF_8))
                            // Zero the intermediate copy. EnrollmentSession holds a CharArray it
                            // can wipe; this ByteArray is ours to clean up.
                            plaintext.fill(0)
                            OpenOutcome.Opened
                        }.getOrElse {
                            // A GCM tag failure here means the blob does not belong to this key.
                            OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed))
                        }
                        cont.resume(outcome)
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        // Every error is Cancelled rather than Failed: dismissal, a hardware
                        // lockout and a user-cancelled prompt are all "try again later", and
                        // none of them says the envelope is broken.
                        cont.resume(OpenOutcome.Cancelled)
                    }
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.email_pgp_unlock_title))
                .setSubtitle(activity.getString(R.string.email_pgp_unlock_subtitle))
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            cont.invokeOnCancellation { prompt.cancelAuthentication() }
        }
    }
}
```

> Match the authenticator set to whatever `VaultSealer`'s implementation uses — the Keystore key was generated with `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`, and a `PromptInfo` narrower than the key's own parameters fails at `authenticate`.

Add to `strings.xml`:

```xml
    <string name="email_pgp_unlock_title">Unlock your mail key</string>
    <string name="email_pgp_unlock_subtitle">Confirm it\'s you to read this encrypted message.</string>
    <string name="email_pgp_unseal_failed">This device\'s key could not be opened. Enrol this device again from Security settings.</string>
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.VaultOpenerContractTest"
./gradlew :app:assembleDebug
```

Expected: tests PASS; the app compiles.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/VaultOpener.kt \
        app/src/main/java/com/urlxl/mail/pgp/VaultOpenerAndroid.kt \
        app/src/test/java/com/urlxl/mail/pgp/VaultOpenerContractTest.kt \
        app/src/main/res/values/strings.xml
git commit -m "feat(pgp): unseal the device envelope for reading

The mirror of VaultSealer. OpenOutcome.Opened carries no key material,
for the same reason the sealer owns its ciphertext end to end: nothing
key-shaped passes back through the orchestrator. The plaintext goes
straight into EnrollmentSession.

This is that holder's first writer. Decision 6 of the ceremony left it
without one deliberately — a process-scoped copy of the account's
private key with zero readers is exposure bought for nothing. The reader
now exists.

Every BiometricPrompt error maps to Cancelled: dismissal, lockout and
user-cancel are all 'try again later', and none says the envelope broke.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: `EncryptedMessageReader` — the orchestrator and the exit table

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/EncryptedMessageReaderTest.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/FakeReaderPorts.kt`

**Interfaces:**
- Consumes: `VaultOpener`/`OpenOutcome` (7), `PgpPayloadClient`/`PgpPayloadResult` (6), `PgpDecryptor`/`DecryptResult` (3), `PgpMimeReader`/`DecryptedBody` (4), `signatureStateFor`/`SignerKey` (5), `EnrollmentSession`.
- Produces:
  ```kotlin
  internal sealed class ReadOutcome {
      data class Decrypted(val body: DecryptedBody, val signature: PgpSignatureState) : ReadOutcome()
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
  internal class EncryptedMessageReader(
      private val opener: VaultOpener,
      private val payloads: PayloadSource,
      private val session: KeyHolder,
  ) { suspend fun read(mailbox: String, messageId: String, sender: String, unlockIfNeeded: Boolean): ReadOutcome }
  ```
  Task 10 consumes `ReadOutcome`.

- [ ] **Step 1: Write the fakes**

Create `app/src/test/java/com/urlxl/mail/pgp/FakeReaderPorts.kt`. `internal`, never `private` — a top-level `private` class compiles to a package-level JVM name and collides.

```kotlin
package com.urlxl.mail.pgp

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

internal fun successPayload(
    encrypted: String = TestPgpPrivateKey.ARMORED_MESSAGE,
    signerKeys: List<SignerKey> = emptyList(),
) = PgpPayloadResult.Success(
    encryptedPayload = encrypted,
    signaturePayload = "",
    body = "",
    signerKeys = signerKeys,
)
```

- [ ] **Step 2: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/EncryptedMessageReaderTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** One test per exit-table row in the design spec. */
class EncryptedMessageReaderTest {

    @After fun cleanup() = EnrollmentSession.clear()

    private fun reader(
        opener: FakeVaultOpener = FakeVaultOpener(),
        payloads: FakePayloadSource = FakePayloadSource(successPayload()),
    ) = EncryptedMessageReader(opener, payloads) to payloads

    private fun read(
        r: EncryptedMessageReader,
        unlockIfNeeded: Boolean = true,
        sender: String = "bob@example.com",
    ) = runBlocking { r.read("INBOX", "42", sender, unlockIfNeeded) }

    @Test
    fun aHeldKeyDecryptsWithoutPrompting() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val opener = FakeVaultOpener()
        val (r, _) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals("must not prompt when the key is already held", 0, opener.opened)
    }

    @Test
    fun aColdSessionAsksForAnUnlockRatherThanPrompting() {
        val opener = FakeVaultOpener()
        val (r, payloads) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertEquals(ReadOutcome.NeedsUnlock, outcome)
        assertEquals("must not prompt on its own", 0, opener.opened)
        assertEquals("must not spend a fetch it cannot use", 0, payloads.fetched)
    }

    @Test
    fun anExplicitUnlockDecrypts() {
        val (r, _) = reader()

        val outcome = read(r, unlockIfNeeded = true)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
    }

    @Test
    fun aDismissedPromptIsCancelledNotAFailure() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Cancelled))

        assertEquals(ReadOutcome.Cancelled, read(r))
    }

    @Test
    fun anUnenrolledDeviceSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NotEnrolled))

        assertEquals(ReadOutcome.NotEnrolled, read(r))
    }

    @Test
    fun noSecureLockScreenSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NoSecureLockScreen))

        assertEquals(ReadOutcome.NoSecureLockScreen, read(r))
    }

    @Test
    fun anUnsealFailureIsDistinctFromACancel() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Failed("key invalidated")))

        assertTrue(read(r) is ReadOutcome.UnsealFailed)
    }

    @Test
    fun aTooLargeMessageSaysSoRatherThanBlamingTheNetwork() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.TooLarge))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)

        assertEquals(ReadOutcome.TooLarge, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aFetchFailureIsRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.Failed("offline")))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)

        assertTrue(read(r, unlockIfNeeded = false) is ReadOutcome.FetchFailed)
    }

    @Test
    fun aFailedDecryptDoesNotClearTheHeldKey() {
        // One bad payload says nothing about the key. Clearing would force a fresh biometric
        // prompt for every later message because of one broken message.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(encrypted = "not a pgp message")))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected DecryptFailed, got $outcome", outcome is ReadOutcome.DecryptFailed)
        assertEquals(TestPgpPrivateKey.ARMORED_PRIVATE, EnrollmentSession.peek())
    }

    @Test
    fun theSignatureVerdictComesFromTheBoundKeyNotTheMessage() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        // The message signs itself with a key we hold no binding for. That is SIGNER_UNKNOWN,
        // never VERIFIED_* — a message that vouches for itself proves only that whoever wrote
        // it owned a key.
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender() {
        // The regression this exists for: if the reader does not hand the bound keys to
        // PgpDecryptor, `valid` stays false, and signatureStateFor maps signed + bound + invalid
        // to INVALID — telling the user that every legitimately signed message from a
        // correspondent they DO hold a key for is an impersonation.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            // A secret key ring's armored form also parses as a public key ring, so the fixture
            // can stand in for the sender's published key.
            publicKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = listOf(bound))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
    }

    @Test
    fun aKeyBoundToADifferentSenderIsNeverOfferedToTheSignatureCheck() {
        // The forgery case, at the reader level. An ordinary contact signs a message and forges
        // the From header to name someone else. If the reader offered the whole address book, the
        // signature would verify against the forger's own key and be attributed to the person
        // named in From. Only keys bound to the DISPLAYED sender may be offered.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val otherContact = SignerKey(
            addresses = listOf("eve@evil.example"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(otherContact))),
        )

        val outcome = read(r, unlockIfNeeded = false, sender = "bob@example.com")
            as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aConflictedKeyIsNeverOfferedToTheSignatureCheck() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            verified = false,
            source = "autocrypt",
            conflict = true,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(conflicted))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.KEY_CHANGED, outcome.signature)
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.EncryptedMessageReaderTest"
```

Expected: FAIL — unresolved reference `EncryptedMessageReader`.

- [ ] **Step 4: Implement the orchestrator**

Create `app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt`:

```kotlin
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
    data class Decrypted(val body: DecryptedBody, val signature: PgpSignatureState) : ReadOutcome()

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

        // `payload.signerKeys` arrives ALREADY narrowed to the displayed sender by
        // `boundSignerKeysForSender` (Task 14). Do not re-narrow here, and do not parse `sender`
        // to do it: a second parser deciding the same binding is exactly the defect Task 15
        // removed — the client's own From parser diverged from the server's on 27 of 111
        // adversarial headers, including RFC 5322 comments, which let any contact forge a verified
        // badge for anyone.
        //
        // Conflicted keys are still dropped here: they carry no key material and must never be
        // offered to a signature check. They stay in `payload.signerKeys` so `signatureStateFor`
        // can report KEY_CHANGED.
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
            return ReadOutcome.Decrypted(parsed, signatureStateFor(raw, payload.signerKeys))
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
        )
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
./gradlew :app:testDebugUnitTest --tests "com.urlxl.mail.pgp.EncryptedMessageReaderTest"
```

Expected: PASS, 13 tests.

- [ ] **Step 6: Prove by deliberate break**

In `read`, temporarily move the `unlockIfNeeded` check so it always prompts. Confirm `aColdSessionAsksForAnUnlockRatherThanPrompting` FAILS on `opener.opened`. Restore.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EncryptedMessageReader.kt \
        app/src/test/java/com/urlxl/mail/pgp/EncryptedMessageReaderTest.kt \
        app/src/test/java/com/urlxl/mail/pgp/FakeReaderPorts.kt
git commit -m "feat(pgp): orchestrate reading one encrypted message

No Android imports, following EnrollmentCeremony — which is what makes
the whole exit table a JVM test with fakes rather than an instrumented
one, including the dismissed-prompt row.

A failed decrypt does not clear the held key: one bad payload says
nothing about the key, and clearing would force a fresh biometric prompt
for every later message.

The key is re-read after the unseal rather than carried from that
branch, because the app can lock in between and lockNow() clears it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Clear the held key on `onTrimMemory`

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/KyPostApp.kt`

**Interfaces:**
- Consumes: `EnrollmentSession.clear()`.
- Produces: nothing.

**Background.** `AppLockManager.lockNow()` **already** clears `EnrollmentSession` (line 98), tested at `AppLockManagerTest.kt:289`. `onTrimMemory` exists nowhere in the app — that half is genuinely unbuilt. Do **not** route this through `InMemoryPlaintext`: its KDoc records that it is deliberately not called from `lockNow()` because the draft cache must survive an ordinary lock. The key holder has the opposite requirement.

**No new unit test, deliberately.** The deliverable is an `Application` lifecycle callback with no JVM seam, and `EnrollmentSession.clear()` is already pinned by `EnrollmentSessionTest`. A test added here would pass before the change as well as after, gating nothing — which the review rubric treats as a defect in its own right. The verification is Step 3's grep and the manual pass in Task 13.

- [ ] **Step 1: Add the callback**

In `app/src/main/java/com/urlxl/mail/KyPostApp.kt`, add to the `Application` subclass:

```kotlin
    /**
     * Drops the opened PGP private key when the system asks for memory back.
     *
     * The plaintext key's lifetime is the exposure, and a trim signal means this process is a
     * candidate for a background kill — after which the heap can outlive any of our teardown. The
     * cost of being wrong is one extra BiometricPrompt.
     *
     * Deliberately NOT routed through `InMemoryPlaintext`. Its KDoc records that it is not called
     * from `AppLockManager.lockNow()` because the compose draft cache must survive an ordinary
     * lock; the key holder has the opposite requirement, so it gets its own call rather than a
     * change to that policy.
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        com.urlxl.mail.pgp.EnrollmentSession.clear()
    }
```

- [ ] **Step 2: Verify it compiles and the suite is green**

```bash
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Confirm the two policies did not get swapped**

```bash
grep -n "EnrollmentSession\|InMemoryPlaintext" app/src/main/java/com/urlxl/mail/KyPostApp.kt \
  app/src/main/java/com/urlxl/mail/security/AppLockManager.kt
```

Expected: `KyPostApp.onTrimMemory` and `AppLockManager.lockNow` both name `EnrollmentSession`; **neither** names `InMemoryPlaintext`.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/KyPostApp.kt
git commit -m "feat(security): drop the opened PGP key on onTrimMemory

lockNow already cleared it; onTrimMemory existed nowhere in the app. A
trim signal means this process may be killed in the background, after
which the heap outlives any teardown we would run. Cost of being wrong
is one extra BiometricPrompt.

Not routed through InMemoryPlaintext: that holder deliberately survives
an ordinary lock so the draft cache does, and the key has the opposite
requirement.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: The padlock, the Decrypt button, and the render

**Files:**
- Create: `app/src/main/res/drawable/ic_lock_large.xml`
- Modify: `app/src/main/res/layout/activity_email_detail.xml`
- Modify: `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt` (`renderPgpBar`, ~398-470)
- Modify: `app/src/main/res/values/strings.xml`

**Interfaces:**
- Consumes: `ReadOutcome` (8), `EncryptedMessageReader` (8), `AndroidVaultOpener` (7), `PgpPayloadClient` (6).
- Produces: nothing.

- [ ] **Step 1: Add the padlock vector**

Create `app/src/main/res/drawable/ic_lock_large.xml`:

```xml
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="96dp"
    android:height="96dp"
    android:viewportWidth="24"
    android:viewportHeight="24"
    android:tint="?android:attr/textColorSecondary">
    <path
        android:fillColor="@android:color/white"
        android:pathData="M18,8h-1L17,6c0,-2.76 -2.24,-5 -5,-5S7,3.24 7,6v2L6,8c-1.1,0 -2,0.9 -2,2v10c0,1.1 0.9,2 2,2h12c1.1,0 2,-0.9 2,-2L20,10c0,-1.1 -0.9,-2 -2,-2zM12,17c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM15.1,8L8.9,8L8.9,6c0,-1.71 1.39,-3.1 3.1,-3.1 1.71,0 3.1,1.39 3.1,3.1v2z" />
</vector>
```

- [ ] **Step 2: Add the placeholder and buttons to the layout**

In `app/src/main/res/layout/activity_email_detail.xml`, add a `Button` for Decrypt and one for Retry inside the `emailPgpBar` `LinearLayout` (id `@+id/emailPgpBar`, ~line 137), beside `btnOpenInWebmail`:

```xml
            <Button
                android:id="@+id/btnDecryptHere"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="@string/email_pgp_decrypt_button"
                android:visibility="gone" />

            <Button
                android:id="@+id/btnRetryPayload"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="@string/email_pgp_retry_button"
                android:visibility="gone" />
```

And immediately before the `WebView` (~line 188), add the placeholder:

```xml
        <ImageView
            android:id="@+id/emailLockedPlaceholder"
            android:layout_width="match_parent"
            android:layout_height="0dp"
            android:layout_weight="1"
            android:contentDescription="@string/email_pgp_locked_placeholder_description"
            android:scaleType="fitCenter"
            android:padding="48dp"
            android:src="@drawable/ic_lock_large"
            android:visibility="gone" />
```

> Match the surrounding layout's width/height/weight idiom — if the `WebView` is not weighted, do not weight this either. Read the file before editing.

- [ ] **Step 3: Add the strings**

```xml
    <string name="email_pgp_decrypt_button">Decrypt here</string>
    <string name="email_pgp_retry_button">Try again</string>
    <string name="email_pgp_locked_placeholder_description">This message is encrypted and is not being shown.</string>
    <string name="email_pgp_can_decrypt_here">This message is end-to-end encrypted. This device holds your key, so it can be opened here.</string>
    <string name="email_pgp_decrypted_here">Decrypted on this device. The server never saw this content.</string>
    <string name="email_pgp_not_enrolled">This message is end-to-end encrypted and this device holds no key. Enrol this device in Security settings, or open it in webmail.</string>
    <string name="email_pgp_hostile_location">This message is end-to-end encrypted. Hostile Location Protection is on, so no key is kept on this device.</string>
    <string name="email_pgp_no_lock_screen">This device needs a screen lock before it can hold your mail key.</string>
    <string name="email_pgp_too_large">This message is too large to open on this device.</string>
    <string name="email_pgp_fetch_failed">Couldn\'t reach the server to fetch this message.</string>
    <string name="email_pgp_decrypt_here_failed">This message couldn\'t be decrypted on this device.</string>
    <string name="email_pgp_reply_disabled">Replying to encrypted mail isn\'t available in the app yet — use webmail.</string>
```

Also correct the now-false line 68:

```xml
    <string name="email_pgp_client_protected">This message is end-to-end encrypted. The server holds no key for it.</string>
```

- [ ] **Step 4: Render the exit table**

In `EmailDetailActivity`, add fields and a render function. Wire the `CLIENT_PROTECTED` branch of `renderPgpBar` to call `attemptDecrypt(unlockIfNeeded = false)` on entry, and hook `btnDecryptHere` to `attemptDecrypt(unlockIfNeeded = true)`.

```kotlin
    private lateinit var lockedPlaceholder: android.widget.ImageView
    private lateinit var btnDecryptHere: Button
    private lateinit var btnRetryPayload: Button

    /** Built lazily: constructing it needs the pairing credential, which is a disk read. */
    private suspend fun encryptedReader(): EncryptedMessageReader? {
        val pairing = PushRuntime.graph(this).repository.pairingForAuthenticatedCall() ?: return null
        val deviceId = pairing.deviceId ?: return null
        val deviceSecret = pairing.deviceSecret ?: return null
        val client = PgpPayloadClient(callFactory = pinnedPairingCallFactory(this))
        return EncryptedMessageReader(
            opener = AndroidVaultOpener(this),
            payloads = object : PayloadSource {
                override suspend fun fetch(mailbox: String, messageId: String) =
                    client.fetch(pairing.serverUrl, deviceId, deviceSecret, mailbox, messageId)
            },
        )
    }

    /**
     * Automatic when the key is already held, explicit when it is not.
     *
     * The prompt stays tied to a deliberate tap so that a dismissal is always a response to
     * something the user just did, rather than a sheet that ambushed a message they opened by
     * accident.
     */
    private fun attemptDecrypt(mailbox: String, messageId: String, sender: String, unlockIfNeeded: Boolean) {
        lifecycleScope.launch {
            val reader = encryptedReader()
            if (reader == null) {
                renderReadOutcome(ReadOutcome.NotEnrolled)
                return@launch
            }
            renderReadOutcome(reader.read(mailbox, messageId, sender, unlockIfNeeded))
        }
    }

    private fun renderReadOutcome(outcome: ReadOutcome) {
        btnDecryptHere.visibility = View.GONE
        btnRetryPayload.visibility = View.GONE

        when (outcome) {
            is ReadOutcome.Decrypted -> {
                // The one path that shows content. The body goes to the WebView and NOWHERE else:
                // not Room, and not fetchedBodyHtml, which feeds reply quoting into
                // ComposeDraftCache and on to POST /api/mail/draft — the server this message was
                // deliberately never readable by.
                lockedPlaceholder.visibility = View.GONE
                webView.visibility = View.VISIBLE
                val html = outcome.body.html
                    ?: "<pre>" + android.text.Html.escapeHtml(outcome.body.plain.orEmpty()) + "</pre>"
                webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null)
                pgpSignatureState = outcome.signature
                pgpText.text = listOfNotNull(
                    getString(R.string.email_pgp_decrypted_here),
                    signatureNoticeFor(outcome.signature),
                ).joinToString("\n")
                btnOpenInWebmail.visibility = View.GONE
            }
            ReadOutcome.NeedsUnlock -> {
                showLocked(getString(R.string.email_pgp_can_decrypt_here))
                btnDecryptHere.visibility = View.VISIBLE
            }
            // Silent on purpose: the user dismissed a sheet they raised. A toast here would be
            // noise about their own action.
            ReadOutcome.Cancelled -> {
                showLocked(getString(R.string.email_pgp_can_decrypt_here))
                btnDecryptHere.visibility = View.VISIBLE
            }
            ReadOutcome.NotEnrolled -> showLocked(getString(R.string.email_pgp_not_enrolled))
            ReadOutcome.NoSecureLockScreen -> showLocked(getString(R.string.email_pgp_no_lock_screen))
            ReadOutcome.TooLarge -> showLocked(getString(R.string.email_pgp_too_large))
            ReadOutcome.NotClientProtected -> showLocked(getString(R.string.email_pgp_client_protected))
            is ReadOutcome.UnsealFailed -> showLocked(getString(R.string.email_pgp_unseal_failed))
            is ReadOutcome.FetchFailed -> {
                showLocked(getString(R.string.email_pgp_fetch_failed))
                btnRetryPayload.visibility = View.VISIBLE
            }
            is ReadOutcome.DecryptFailed -> showLocked(getString(R.string.email_pgp_decrypt_here_failed))
        }
    }

    /** The padlock and the webmail button always appear together: one says "not readable here",
     *  the other says "readable there". */
    private fun showLocked(notice: String) {
        webView.visibility = View.GONE
        lockedPlaceholder.visibility = View.VISIBLE
        pgpBar.visibility = View.VISIBLE
        pgpText.text = notice
    }
```

Extract the existing `when (pgpSignatureState)` block from `renderPgpBar` into `signatureNoticeFor(state: PgpSignatureState): String?` so both call sites use one copy.

`btnOpenInWebmail`'s existing visibility logic in the `CLIENT_PROTECTED` branch is unchanged — `showLocked` leaves it as `renderPgpBar` set it.

- [ ] **Step 5: Build and check the states by hand on an emulator or device**

```bash
./gradlew :app:assembleDebug
```

Expected: BUILD SUCCESSFUL. Install and confirm rows 1, 3, 5 and 12 of the exit table by hand. Full coverage is Task 13.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/res/drawable/ic_lock_large.xml \
        app/src/main/res/layout/activity_email_detail.xml \
        app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt \
        app/src/main/res/values/strings.xml
git commit -m "feat(mail): read client-protected messages on the device

The CLIENT_PROTECTED branch becomes a ladder. Whenever 'Open in webmail'
is visible the body is replaced by a padlock — the two always appear
together, one saying 'not readable here' and the other 'readable there'.

Decryption is automatic when the key is already held and explicit when
it is not, so the biometric sheet always follows a tap rather than
ambushing a message opened by accident. A dismissed prompt is silent.

The decrypted body reaches the WebView and nothing else: not Room, and
not fetchedBodyHtml, which feeds reply quoting into ComposeDraftCache
and on to POST /api/mail/draft.

email_pgp_client_protected no longer claims only the browser holds the
key.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: Disable Reply, Reply-All and Forward on client-protected messages

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt`

**Interfaces:**
- Consumes: `PgpMessageState.CLIENT_PROTECTED`.
- Produces: nothing.

**Background.** `POST /api/mail/draft` uploads the draft **to the server**. Quoting a decrypted body into a reply would hand the server the plaintext of a message it was deliberately never able to read. There is no encrypted send path yet, so there is no safe destination for these actions.

- [ ] **Step 1: Disable the three buttons and explain why**

In `EmailDetailActivity`, where `pgpState` is known (the render block around line 309), add:

```kotlin
            // Disabled for every CLIENT_PROTECTED message, decrypted or not.
            //
            // POST /api/mail/draft uploads to the server. Quoting a decrypted body into a reply
            // would hand the server the plaintext of a message this whole mode exists to keep from
            // it — at one tap, with no warning. There is no encrypted send path in the app yet, so
            // there is no safe destination for any of these.
            //
            // Unconditional rather than gated on decrypt success: a button that starts working
            // once a message opens teaches the user a rule that is not true.
            if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
                listOf(actionReply, actionReplyAll, actionForward).forEach {
                    it.isEnabled = false
                    it.alpha = 0.4f
                    it.setOnClickListener {
                        Toast.makeText(
                            this,
                            R.string.email_pgp_reply_disabled,
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }
            }
```

- [ ] **Step 2: Ensure the decrypted body never reaches `fetchedBodyHtml`**

Find the `fetchedBodyHtml = content?.html` assignment and confirm it is not reachable for `CLIENT_PROTECTED`. If the render path can reach it, guard it:

```kotlin
            // Never for a client-protected message: this field feeds reply quoting, which feeds
            // ComposeDraftCache, which feeds POST /api/mail/draft.
            if (pgpState != PgpMessageState.CLIENT_PROTECTED) {
                fetchedBodyHtml = content?.html
            }
```

- [ ] **Step 3: Verify by grep that no decrypted path writes the field**

```bash
grep -n "fetchedBodyHtml" app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt
```

Expected: every assignment is either inside the non-`CLIENT_PROTECTED` guard or reads from server-supplied content, and none reads from `ReadOutcome.Decrypted`.

- [ ] **Step 4: Build and run the suite**

```bash
./gradlew :app:assembleDebug :app:testDebugUnitTest
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/EmailDetailActivity.kt
git commit -m "feat(mail): disable reply and forward on client-protected messages

POST /api/mail/draft uploads the draft to the server, so quoting a
decrypted body into a reply would hand the server the plaintext of a
message this mode exists to keep from it — one tap, no warning. There is
no encrypted send path in the app yet, so there is no safe destination.

Unconditional rather than gated on decrypt success: a button that starts
working once a message opens teaches a rule that is not true.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 12: Correct the obsolete contract in `AGENTS.md`

**Files:**
- Modify: `app/src/main/AGENTS.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

**Background.** `app/src/main/AGENTS.md` states as a local contract: *"this app cannot decrypt it"* and *"Deliberately no on-device private key: the phone pairs by QR and never learns the account password… Do not add one without revisiting that decision."* That decision **was** revisited — the enrollment ceremony shipped a device-sealed envelope, and this work reads it. Left as-is, the file instructs every future agent to preserve a constraint the code no longer has.

- [ ] **Step 1: Rewrite the PGP contract paragraph**

Replace the sentence *"Deliberately no on-device private key… Do not add one without revisiting that decision."* with:

```markdown
  **There IS an on-device private key, and this replaced the earlier "deliberately none" contract.**
  The device enrollment ceremony seals the account's PGP private key into a StrongBox/TEE AES-GCM
  envelope with `setUserAuthenticationRequired(true)` (`pgp/EnrollmentVault`), and no passphrase is
  ever typed on the phone — which is what made the old objection ("the phone never learns the
  account password") stop applying. `pgp/EncryptedMessageReader` unseals it through
  `pgp/VaultOpener`, holds it in `pgp/EnrollmentSession` for the configured lock window, and
  decrypts client-protected messages locally. So `CLIENT_PROTECTED` no longer means "cannot be read
  here": it means "not readable here **unless** this device is enrolled and unlocked". Webmail
  remains the fallback for every device that is not.
  Hostile Location Protection destroys the envelope and is the mode in which none of this exists.
```

- [ ] **Step 2: Correct the row-marker sentence in the same file**

The existing text says `pgpRowMarker` marks "🔒 client-protected, ⚠ decrypt failed". Append:

```markdown
  A failed signature or a CHANGED signer key (`PgpSignatureState.KEY_CHANGED`) outranks both with
  ⚠. `SIGNER_UNKNOWN` deliberately does not mark: it is the ordinary state for a correspondent not
  yet in the address book, and a glyph on most rows carries nothing actionable.
```

- [ ] **Step 3: Verify no other file repeats the stale claim**

```bash
grep -rn "cannot decrypt\|no on-device private key\|Only your browser holds the key" \
  app/src/main/ docs/ README.md 2>/dev/null
```

Expected: no remaining occurrence outside historical spec/plan documents, which are records of their date and are left alone.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/AGENTS.md
git commit -m "docs(agents): the 'no on-device private key' contract is obsolete

AGENTS.md still told every future agent that this app cannot decrypt
client-protected mail and must not add an on-device key without
revisiting that decision. It was revisited: the enrollment ceremony
shipped a device-sealed envelope and this branch reads it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 13: The manual acceptance pass

**Files:** none.

**Interfaces:**
- Consumes: everything above, deployed to a real phone against a real server.
- Produces: a recorded result.

**Background.** Reading is not done until an actual encrypted message, sent from webmail, opens on the phone with the right signature verdict. Two clients agreeing via unit tests and a shared vector is precisely the kind of agreement that has already been wrong twice on this feature — the 4-3-4-3 grouping mismatch and the dismissed-prompt state both survived full suites.

- [ ] **Step 1: Deploy both sides**

Deploy the `kypost-server` branch from Tasks 1-2 and install the app:

```bash
./gradlew :app:installDebug
```

- [ ] **Step 2: Confirm the flag fix on a non-INBOX folder**

Send an encrypted message from webmail and file it into a folder the poller never touches (anything other than INBOX — Archive works). Pull to refresh the phone twice. Expected: the row shows 🔒 on **both** refreshes. Before Task 1 the second refresh reported it as ordinary mail.

- [ ] **Step 3: Walk the exit table**

| Check | Expected |
|---|---|
| Cold session — open the message | Padlock + "Decrypt here" + "Open in webmail"; **no** prompt until tapped |
| Tap "Decrypt here" | BiometricPrompt, then the body |
| Open a second encrypted message | Body, **no** prompt |
| Dismiss the prompt (cold session) | Back to the padlock + Decrypt button, **no** toast |
| Lock the app, return, open an encrypted message | Padlock + Decrypt button — the prompt is back |
| Message from a contact not in the address book | "signed, but you hold no key for this sender" |
| Message from a contact with a QR-confirmed key | "verified against a key you confirmed" |
| Reply / Reply-All / Forward | Greyed; tapping shows the webmail notice |
| Enable Hostile Location Protection, reopen | Padlock, no Decrypt button |

- [ ] **Step 4: Confirm the decrypted body did not land on disk**

```bash
adb shell run-as com.urlxl.mail ls -la databases/
adb shell run-as com.urlxl.mail sqlite3 databases/<db> \
  "select substr(body,1,80) from emails where pgpEncrypted=1;"
```

Expected: empty bodies for every client-protected row. A non-empty one is a release blocker — see the non-negotiable rules.

- [ ] **Step 5: Fold in the two carried-over ceremony gaps**

Both are cheap while a device is in hand and neither has ever been seen by a human:

- Dismiss the enrollment fingerprint prompt and confirm the `ReadyToFinish` state added in #23 renders.
- Let a 120-second enrollment bucket roll with the prompt up, and confirm the code refreshes rather than failing.

- [ ] **Step 6: Record the result**

Append a dated "Acceptance run" section to
`docs/superpowers/specs/2026-08-07-on-device-encrypted-mail-reading-design.md` recording what was run, on what hardware, and anything that failed. The ceremony's own run is recorded the same way in commit `234c5c3` — the point is that the next session starts from a fact rather than an assumption.

- [ ] **Step 7: Commit**

```bash
git add docs/superpowers/specs/2026-08-07-on-device-encrypted-mail-reading-design.md
git commit -m "docs: record the encrypted-mail reading acceptance run

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage.** Part 0.1 → Task 1. Part 0.2 → Task 2. `VaultOpener` → 7. `PgpPayloadClient` → 6. `PgpDecryptor` → 3. `PgpMimeReader` → 4. `SignerBinding` → 5. `EncryptedMessageReader` → 8. Unlock model → 8 (`unlockIfNeeded`) + 10 (wiring). Exit table → 8 (tests) + 10 (render). Six signature states → 5. Padlock → 10. Reply/Forward disabled + `fetchedBodyHtml` → 11. `onTrimMemory` → 9. HLP gate → covered by the existing `EnrollmentTeardown`; Task 13 Step 3 verifies it, and this work adds no new key-holding store that would need its own teardown step. Attachment reason gate → recorded in the spec, no task by design. Acceptance test → 13. AGENTS.md correction → 12 (not in the spec; found during planning).

**Type consistency.** `RawSignature` (3) → consumed by `signatureStateFor` (5) and `EncryptedMessageReader` (8). `SignerKey` (5) → produced by `PgpPayloadClient` (6), consumed by 5 and 8. `DecryptedBody` (4) → `ReadOutcome.Decrypted` (8) → `renderReadOutcome` (10). `OpenOutcome` (7) → 8. `PgpPayloadResult` (6) → 8. `PayloadSource` declared in 8, implemented anonymously in 10. Wire names `verified`/`source`/`conflict` are identical in Task 2's Go struct tags and Task 6's `SignerKeyDto`.

**Known rough edge, flagged rather than hidden.** Task 3 Step 4 ships `verifyOnePass` returning `valid = false` with an implementer note to complete it against a caller-supplied public key. That is the one place in this plan where a step hands over an incomplete function rather than a finished one — it is unavoidable, because one-pass verification needs the signer key that Task 5 defines the binding for, and inverting the task order would make `SignerBinding` untestable. The note states exactly what to change and the two `PgpDecryptorTest` signature assertions fail until it is done.

---

# Part 0b — the server resolves the sender

Added 2026-08-07, after a differential harness (111 adversarial headers against Go's
`net/mail.ParseAddressList`) found 27 divergences in the client's hand-rolled `senderAddrSpec`,
including a Critical: RFC 5322 **comments** are invisible to it.

`From: Bob Smith (Eve <eve@evil.com>) <bob@x.com>` is valid RFC 5322. Go and the server bind
`bob@x.com`; the client bound `eve@evil.com`. Eve — any ordinary contact — signs with her own key
and the badge reads verified. The key-id binding added earlier does not help: the key that signed
genuinely *is* bound to the address the client resolved. The comment is arbitrary-length, so the
decoy hides inside a plausible gateway banner.

Three fix rounds addressed three constructs (last-vs-first mailbox, quoted display name, comments),
each defect introduced by the previous fix. Comments nest, quoted strings and comments have
different escape rules, and `\` means different things inside and outside a quoted string. **The
client stops parsing `From` altogether.** The server already owns a parser that has survived three
attempts; it becomes the single binding authority.

These two tasks run **before** Tasks 6-13.

### Task 14: `handlePGPPayload` returns keys already narrowed to the sender

**Files:**
- Modify: `backend/internal/adapters/imap/client.go` — add `Sender` to `MessageContent`, populate in `GetMessageBodies`
- Modify: `backend/internal/api/pgp_receive.go` — add `boundSignerKeysForSender`
- Modify: `backend/internal/api/pgp_client_read.go` — narrow `signerKeys`, return the resolved sender
- Test: `backend/internal/api/pgp_receive_test.go`

**Interfaces:**
- Consumes: `senderAddrSpec`, `contactBindsAddress`, `keyMatchesPin` (all existing in `pgp_receive.go`).
- Produces: `GET /api/mail/pgp-payload` gains `"sender"` (raw `From`) and `"resolvedSender"` (the parsed addr-spec), and its `signerKeys` array now contains **only** keys bound to that sender. Task 15 consumes both.

**Why no extra IMAP round trip.** `GetMessageBodies` already holds `*goimap.Email`, and `client.go:594`
shows `e.From.String()` is available on that type. Adding one field costs nothing on the wire to IMAP.

- [ ] **Step 1: Write the failing test**

Add to `backend/internal/api/pgp_receive_test.go`. Reuse the fixture idiom already in that file
(`pgpVictimWithIdentity` + `pgpmail.GenerateIdentity` + `store.Upsert`) — read it first, do not
invent a second style.

```go
// The client no longer parses From at all, so this narrowing IS the binding.
// A key bound to some OTHER contact must never reach a client that is
// displaying this sender.
func TestBoundSignerKeysForSenderExcludesOtherContacts(t *testing.T) {
	store := newContactsStoreForTest(t)
	upsertContactWithKey(t, store, "bob@example.com", /*verified=*/ true, "qr")
	upsertContactWithKey(t, store, "eve@evil.example", /*verified=*/ false, "autocrypt")

	got := boundSignerKeysForSender(store, "bob@example.com")

	if len(got) != 1 {
		t.Fatalf("want only the sender's key, got %d: %+v", len(got), got)
	}
	if got[0].Addresses[0] != "bob@example.com" || !got[0].Verified {
		t.Fatalf("wrong key or lost provenance: %+v", got[0])
	}
}

// The RFC 5322 comment attack, at the layer that now owns the decision.
// Go's mail.ParseAddressList binds the real mailbox; the decoy inside the
// comment must not select Eve's key.
func TestBoundSignerKeysForSenderIgnoresAnAddressHiddenInAComment(t *testing.T) {
	store := newContactsStoreForTest(t)
	upsertContactWithKey(t, store, "bob@example.com", true, "qr")
	upsertContactWithKey(t, store, "eve@evil.example", false, "autocrypt")

	resolved := senderAddrSpec("Bob Smith (Eve <eve@evil.example>) <bob@example.com>")
	got := boundSignerKeysForSender(store, resolved)

	if resolved != "bob@example.com" {
		t.Fatalf("senderAddrSpec bound the decoy: %q", resolved)
	}
	if len(got) != 1 || got[0].Addresses[0] != "bob@example.com" {
		t.Fatalf("comment decoy selected the wrong key: %+v", got)
	}
}

// A conflicted key for THIS sender must still be reported, with no key
// material — it is the only way the client can say the key changed.
func TestBoundSignerKeysForSenderStillReportsAConflict(t *testing.T) {
	store := newContactsStoreForTest(t)
	upsertContactWithConflictingPin(t, store, "bob@example.com")

	got := boundSignerKeysForSender(store, "bob@example.com")

	if len(got) != 1 || !got[0].Conflict {
		t.Fatalf("want a conflict marker, got %+v", got)
	}
	if got[0].PublicKey != "" {
		t.Fatal("a conflicted key must ship no key material")
	}
}
```

> Name the helpers to match whatever the file already uses; the three used above are placeholders for
> that file's real idiom. Do **not** add a second fixture style.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run 'TestBoundSignerKeysForSender' -v
```

Expected: FAIL to compile — `boundSignerKeysForSender` undefined.

- [ ] **Step 3: Add `Sender` to `MessageContent`**

In `backend/internal/adapters/imap/client.go`, add to `type MessageContent struct`:

```go
	// Sender is the raw From header, exactly as ListOverviews reports it
	// (`Name <addr>` when a display name is present).
	//
	// Carried here so handlePGPPayload can resolve the signature binding with
	// the SAME parser the rest of the server uses. The Android client used to
	// parse this header itself, and a differential harness found 27 divergences
	// from net/mail.ParseAddressList — including RFC 5322 comments, where
	// `Bob (Eve <eve@evil>) <bob@x>` is valid and the client bound Eve. One
	// parser, server-side, removes that entire class.
	//
	// Free: GetMessageBodies already holds the *goimap.Email this comes from.
	Sender string
```

and in `GetMessageBodies`'s per-UID loop, where `content` is built:

```go
		content := MessageContent{
			Body:           body,
			BodyMode:       bodyMode,
			HasAttachments: len(e.Attachments) > 0,
			Sender:         strings.TrimSpace(e.From.String()),
		}
```

- [ ] **Step 4: Add `boundSignerKeysForSender`**

In `backend/internal/api/pgp_receive.go`, beside `boundSignerKeys`:

```go
// boundSignerKeysForSender is boundSignerKeys narrowed to one sender.
//
// This is now THE signature binding for the Android client, which no longer
// parses the From header at all. Its hand-rolled parser diverged from
// net/mail.ParseAddressList on 27 of 111 adversarial headers — most seriously
// on RFC 5322 comments, where `Bob (Eve <eve@evil>) <bob@x>` is a valid header
// that Go binds to bob@x and the client bound to eve@evil, letting any contact
// forge a verified badge for anyone. Three client-side fix rounds each closed
// one construct and opened another. Shipping the decision instead of the inputs
// removes the second parser, exactly as boundSignerKeys' own comment says of
// the browser.
//
// address must already be a bare addr-spec from senderAddrSpec. An empty
// address matches nothing, which is the safe direction: no keys, so no verdict
// beyond "signed, but not by a key you hold for this sender".
func boundSignerKeysForSender(store *contacts.Store, address string) []boundSignerKey {
	out := []boundSignerKey{}
	if address == "" {
		return out
	}
	for _, k := range boundSignerKeys(store) {
		for _, a := range k.Addresses {
			if a == address {
				out = append(out, k)
				break
			}
		}
	}
	return out
}
```

- [ ] **Step 5: Use it in the handler**

In `backend/internal/api/pgp_client_read.go`, replace the `signerKeys` block:

```go
	// The sender the client will display, and the addr-spec the binding uses.
	// Both are shipped: the client renders one and binds on the other, and it
	// must never re-derive the second from the first. See boundSignerKeysForSender.
	sender := strings.TrimSpace(content.Sender)
	resolvedSender := senderAddrSpec(sender)

	signerKeys := []boundSignerKey{}
	if contactsStore, cerr := s.userContactsStore(ac.UserID); cerr == nil {
		signerKeys = boundSignerKeysForSender(contactsStore, resolvedSender)
	}
```

and add both fields to the response map:

```go
		"sender":         sender,
		"resolvedSender": resolvedSender,
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run 'TestBoundSignerKeysForSender' -v && go test ./internal/...
```

Expected: PASS.

- [ ] **Step 7: Prove by deliberate break**

Change `boundSignerKeysForSender` to `return boundSignerKeys(store)` (un-narrowed). Confirm
`TestBoundSignerKeysForSenderExcludesOtherContacts` FAILS. Restore.

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/adapters/imap/client.go backend/internal/api/pgp_receive.go \
        backend/internal/api/pgp_client_read.go backend/internal/api/pgp_receive_test.go
git commit -m "feat(pgp): bind signer keys to the sender server-side

The Android client parsed the From header itself to decide which key a
signature binds to. A differential harness over 111 adversarial headers
found 27 divergences from net/mail.ParseAddressList, the worst being RFC
5322 comments: 'Bob (Eve <eve@evil>) <bob@x>' is valid, Go binds bob@x,
the client bound eve@evil — so any contact could forge a verified badge
for anyone. Three client fix rounds each closed one construct and opened
another.

The payload endpoint now ships keys already narrowed to the sender, plus
the raw and resolved sender, so the client stops parsing headers. Same
argument boundSignerKeys already makes for the browser: ship the binding,
not the inputs.

MessageContent gains Sender at no IMAP cost — GetMessageBodies already
holds the goimap.Email it comes from.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 15: delete the client's `From` parser

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt`
- Modify: `app/src/test/java/com/urlxl/mail/pgp/SignerBindingTest.kt`

**Interfaces:**
- Consumes: `signerKeys` from Task 14, already narrowed to the sender.
- Produces: `signatureStateFor(signature: RawSignature, signerKeys: List<SignerKey>): PgpSignatureState` — **the `senderAddress` parameter is gone.** Task 8 consumes this shape.

- [ ] **Step 1: Delete the parser and its tests**

Remove from `SignerBinding.kt`: `senderAddrSpec`, `firstMailboxText`, `addrSpecFromMailbox`,
`looksLikeAddrSpec`, `firstUnquotedAngleOpen`, and every helper that exists only to serve them.
Remove the corresponding tests from `SignerBindingTest.kt` (the mailbox-parsing cases). Keep every
test about verdicts.

- [ ] **Step 2: Narrow `signatureStateFor`'s signature**

```kotlin
/**
 * The signature verdict for a message being displayed as being from a sender the **server** has
 * already resolved.
 *
 * [signerKeys] arrives narrowed to that sender by `boundSignerKeysForSender`. This function does
 * not know the sender's address and must not learn it: the client used to parse the raw `From`
 * header itself, and a differential harness over 111 adversarial headers found 27 divergences from
 * the server's parser — most seriously RFC 5322 comments, where `Bob (Eve <eve@evil>) <bob@x>` is
 * valid, the server binds `bob@x`, and the client bound `eve@evil`, letting any contact forge a
 * verified badge for anyone. Three fix rounds each closed one construct and opened another.
 *
 * A second parser deciding the same binding is the defect. Do not reintroduce one.
 */
internal fun signatureStateFor(
    signature: RawSignature,
    signerKeys: List<SignerKey>,
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE
    if (signerKeys.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN
    if (signerKeys.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    val signedBy = signerKeys.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    if (signedBy.isEmpty()) return PgpSignatureState.SIGNER_UNKNOWN
    if (!signature.valid) return PgpSignatureState.INVALID

    return if (signedBy.any { it.verified }) {
        PgpSignatureState.VERIFIED_CONFIRMED
    } else {
        PgpSignatureState.VERIFIED_SEEN_BEFORE
    }
}
```

- [ ] **Step 3: Add the regression test that pins the deletion**

```kotlin
    @Test
    fun theClientHoldsNoSenderParserOfItsOwn() {
        // The binding is the server's, shipped already narrowed. If someone reintroduces a
        // From-header parser here, this fails to compile — which is the point. See the KDoc on
        // signatureStateFor for the 27-divergence harness that made this a rule.
        val state = signatureStateFor(
            RawSignature(present = true, valid = true, signerKeyId = 0L),
            emptyList(),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }
```

- [ ] **Step 4: Run the tests**

```bash
./gradlew :app:testDebugUnitTest
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/SignerBinding.kt \
        app/src/test/java/com/urlxl/mail/pgp/SignerBindingTest.kt
git commit -m "fix(pgp): stop parsing the From header on the client

A differential harness over 111 adversarial headers found 27 divergences
from the server's parser. The worst: RFC 5322 comments were invisible, so
'Bob (Eve <eve@evil>) <bob@x>' — a valid header — bound to Eve while the
server bound Bob, letting any contact in the address book forge a
verified badge for anyone. Three fix rounds each closed one construct
(last-vs-first mailbox, quoted display name, comments) and opened
another; comments nest and escape differently inside and outside quoted
strings, so the next round would have been the same shape.

The server now ships keys already narrowed to the sender, so the second
parser is deleted rather than patched.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```
