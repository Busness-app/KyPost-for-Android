# Mobile Encrypted Send — kypost-android Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a server-custody account send signed and encrypted mail from the Android app, and hand a client-custody account off to webmail instead of failing.

**Architecture:** The app never does OpenPGP. It sets `sign`/`encrypt`/`allowPickupFallback` on `/api/mail/send` and lets the server do the crypto. What custody mode is in force comes from `GET /api/pgp/bootstrap`; which recipients lack keys comes from `POST /api/pgp/recipients/check`. Client-custody compose saves a draft and opens webmail.

**Tech Stack:** Kotlin, OkHttp, kotlinx.serialization, JUnit4 with hand-rolled fakes (no mocking framework — see `RelayMailSourceTest.kt:29`).

**Depends on:** the server plan in `kypost-server/docs/superpowers/plans/2026-07-25-mobile-encrypted-send-server.md`. Tasks 1-6 here can be written and unit-tested before the server ships; only manual verification needs it deployed.

**Spec:** `kypost-server/docs/superpowers/specs/2026-07-25-mobile-encrypted-send-design.md`

## Global Constraints

- The app holds **no private key** and does **no OpenPGP**. If a task seems to need Bouncy Castle, it is the wrong task.
- `allowPickupFallback` is sent as `true` only after the user confirms a dialog naming the keyless recipients. Never default it on.
- "Couldn't check" is never "no" — a failed bootstrap hides the PGP controls rather than guessing a custody mode. This mirrors the rule already documented at `PgpIdentityStatus.kt:31-34`.
- Encrypt does **not** require the account to have a PGP identity; Sign does. They are separate conditions (server: `server.go:1199-1208`).
- The webmail handoff hands the URL to the **system**, never an in-app WebView (`kypost-server/docs/E2E_PGP.md:344-348`).
- Test style: hand-rolled fakes, no mocking framework.

## File Structure

| File | Responsibility |
|---|---|
| `mail/MailSource.kt` | `MailDraft` flags; `MailOutcome.PickupFallbackNeeded`; its user-facing copy |
| `mail/RelayModels.kt` | `RelayMailRequestDto` flags; the 409 body DTO |
| `mail/RelayMailSource.kt` | `toSendWireDto()`; 409 discrimination |
| `pgp/PgpComposeState.kt` (new) | Pure function: bootstrap → which compose controls exist |
| `pgp/PgpBootstrapClient.kt` (new) | `GET /api/pgp/bootstrap` |
| `pgp/RecipientKeyClient.kt` (new) | `POST /api/pgp/recipients/check` |
| `pgp/WebmailDeepLink.kt` | Gains `webmailDraftsUrl` |
| `ComposePgpController.kt` (new) | Preflight, send gate, handoff — keeps `ComposeActivity` a view |
| `ComposeActivity.kt` | Owns the controller; renders toggles and dialogs |

---

### Task 1: Send the PGP flags on the wire

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/mail/MailSource.kt:81-89` (`MailDraft`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayModels.kt:106-115` (`RelayMailRequestDto`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayMailSource.kt:348` (`toWireDto`) and `:205-218` (`sendMail`)
- Test: `app/src/test/java/com/urlxl/mail/mail/RelayMailSourceTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `MailDraft(sign: Boolean, encrypt: Boolean, allowPickupFallback: Boolean)`, and `MailDraft.toSendWireDto(): RelayMailRequestDto`

**Note on drafts:** `toWireDto()` is called by *both* `sendMail` and `saveDraft` (`RelayMailSource.kt:198,208`). Drafts have no crypto semantics — the server's `SaveDraft` ignores the flags entirely — so a second mapper keeps `saveDraft` from claiming a choice it isn't making. Do not add the flags to the shared `toWireDto()`.

- [ ] **Step 1: Write the failing test**

Append to `RelayMailSourceTest.kt`:

```kotlin
@Test
fun sendMail_putsPgpFlagsOnTheWire() {
    var capturedBody = ""
    val source = RelayMailSource(
        pairingProvider = { testPairing() },
        callFactory = recordingCallFactory(
            onRequest = { capturedBody = it },
            responseCode = 200,
            responseBody = """{"ok":true,"sentSaved":true,"warning":""}""",
        ),
    )

    source.sendMail(
        MailDraft(
            to = "bob@example.com", subject = "hi", body = "hello",
            sign = true, encrypt = true, allowPickupFallback = true,
        )
    )

    assertTrue(capturedBody.contains("\"sign\":true"))
    assertTrue(capturedBody.contains("\"encrypt\":true"))
    assertTrue(capturedBody.contains("\"allowPickupFallback\":true"))
}

/** Drafts carry no crypto semantics — the server ignores the flags on
 *  /api/mail/draft — so sending them would claim a choice the user did not
 *  make at draft-save time. */
@Test
fun saveDraft_omitsPgpFlags() {
    var capturedBody = ""
    val source = RelayMailSource(
        pairingProvider = { testPairing() },
        callFactory = recordingCallFactory(
            onRequest = { capturedBody = it },
            responseCode = 200,
            responseBody = """{"ok":true}""",
        ),
    )

    source.saveDraft(MailDraft(to = "bob@example.com", subject = "hi", body = "hello", encrypt = true))

    assertTrue(!capturedBody.contains("encrypt"))
    assertTrue(!capturedBody.contains("allowPickupFallback"))
}
```

`recordingCallFactory` is a helper you write in the same file, following the existing hand-rolled fake style in `RelayMailSourceTest.kt:29-50` — it captures the request body string and returns a canned `Response`. Check the file for an existing fake that already does this before adding another; reuse beats duplication.

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: FAIL — `MailDraft` has no `sign` parameter.

- [ ] **Step 3: Add the fields and the send-only mapper**

`MailSource.kt`, in `MailDraft`:

```kotlin
    /** Server-side PGP signing. Requires the account to have a PGP identity. */
    val sign: Boolean = false,
    /** Server-side PGP encryption. Needs only the recipients' public keys —
     *  works with no sender identity at all. */
    val encrypt: Boolean = false,
    /** Opt in to the one-time pickup link for recipients with no key. Only ever
     *  true after the user confirmed the dialog naming them: the fallback
     *  stores this message's plaintext on the server for seven days. */
    val allowPickupFallback: Boolean = false,
```

`RelayModels.kt`, in `RelayMailRequestDto`, after `attachments`:

```kotlin
    val sign: Boolean = false,
    val encrypt: Boolean = false,
    val allowPickupFallback: Boolean = false,
```

`RelayMailSource.kt`, beside the existing `toWireDto` at `:348`:

```kotlin
/** Send-only mapping. [toWireDto] stays flagless for /api/mail/draft, whose
 *  handler ignores these fields — see MailDraft's own docs. */
private fun MailDraft.toSendWireDto(): RelayMailRequestDto =
    toWireDto().copy(sign = sign, encrypt = encrypt, allowPickupFallback = allowPickupFallback)
```

Change `sendMail` (`:208`) to `json.encodeToString(draft.toSendWireDto())`. Leave `saveDraft` (`:198`) calling `toWireDto()`.

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/mail/ app/src/test/java/com/urlxl/mail/mail/
git commit -m "feat(pgp): send sign/encrypt/allowPickupFallback on the relay send"
```

---

### Task 2: Recognize the keyless-recipient 409

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/mail/MailSource.kt` (`MailOutcome`, `userFacingMessage`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayModels.kt` (new response DTO)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayMailSource.kt:296-301` (the 409 branch)
- Test: `app/src/test/java/com/urlxl/mail/mail/RelayMailSourceTest.kt`

**Interfaces:**
- Consumes: Task 1
- Produces: `MailOutcome.PickupFallbackNeeded(val keylessRecipients: List<String>, val message: String)`

- [ ] **Step 1: Write the failing test**

```kotlin
@Test
fun send409WithKeylessRecipients_mapsToPickupFallbackNeeded() {
    val source = RelayMailSource(
        pairingProvider = { testPairing() },
        callFactory = cannedCallFactory(
            code = 409,
            body = """{"error":"no key","keylessRecipients":["carol@example.com"],"pickupFallbackAvailable":true}""",
        ),
    )

    val outcome = source.sendMail(MailDraft(to = "carol@example.com", subject = "hi", body = "hello", encrypt = true))

    val needed = outcome as MailOutcome.PickupFallbackNeeded
    assertEquals(listOf("carol@example.com"), needed.keylessRecipients)
}

/** Both refusals are 409. A client-custody account must keep resolving to
 *  ClientSideNeeded — offering it a pickup-link dialog would answer a question
 *  it never got to ask. */
@Test
fun send409WithClientSideNeeded_stillMapsToClientSideNeeded() {
    val source = RelayMailSource(
        pairingProvider = { testPairing() },
        callFactory = cannedCallFactory(code = 409, body = """{"error":"e2e","clientSideNeeded":true}"""),
    )

    val outcome = source.sendMail(MailDraft(to = "bob@example.com", subject = "hi", body = "hello", encrypt = true))

    assertTrue(outcome is MailOutcome.ClientSideNeeded)
}

/** An unrecognized 409 must not silently become a pickup-fallback prompt. */
@Test
fun send409WithNeitherMarker_isBadRequest() {
    val source = RelayMailSource(
        pairingProvider = { testPairing() },
        callFactory = cannedCallFactory(code = 409, body = """{"error":"something else"}"""),
    )

    val outcome = source.sendMail(MailDraft(to = "bob@example.com", subject = "hi", body = "hello"))

    assertTrue(outcome is MailOutcome.BadRequest)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: FAIL — `MailOutcome.PickupFallbackNeeded` unresolved.

- [ ] **Step 3: Add the outcome, the DTO, and the branch**

`MailSource.kt`, in the `MailOutcome` sealed class:

```kotlin
    /** Relay 409 on /api/mail/send carrying `keylessRecipients` — one or more
     *  recipients have no usable PGP key, and the server refused rather than
     *  quietly falling back to a one-time link that stores this message's
     *  plaintext for seven days. Recoverable: re-send with
     *  [MailDraft.allowPickupFallback] once the user has confirmed. */
    data class PickupFallbackNeeded(
        val keylessRecipients: List<String>,
        val message: String,
    ) : MailOutcome<Nothing>()
```

In `userFacingMessage()`, add a branch — it is a `when` over a sealed class, so omitting it will not compile:

```kotlin
    is MailOutcome.PickupFallbackNeeded ->
        "No PGP key for ${keylessRecipients.joinToString(", ")}. Send them a one-time link instead, or remove them."
```

`RelayModels.kt`:

```kotlin
/** The 409 body /api/mail/send returns when recipients have no usable PGP key.
 *  Both PGP refusals are 409 and are told apart by which field is present, not
 *  by status or message prose. */
@Serializable
data class RelayPickupFallbackDto(
    val error: String = "",
    val keylessRecipients: List<String> = emptyList(),
    val pickupFallbackAvailable: Boolean = false,
)
```

`RelayMailSource.kt`, replacing the 409 branch at `:296-301`:

```kotlin
        // Two PGP refusals share this status and are discriminated by field.
        // clientSideNeeded is checked first to match the server's own
        // precedence: a client-custody account cannot encrypt server-side at
        // all, so its keyless recipients are beside the point.
        409 -> when {
            rawBody.contains(CLIENT_SIDE_NEEDED_MARKER, ignoreCase = true) -> MailOutcome.ClientSideNeeded(rawBody)
            else -> {
                val parsed = runCatching { json.decodeFromString<RelayPickupFallbackDto>(rawBody) }.getOrNull()
                if (parsed != null && parsed.keylessRecipients.isNotEmpty()) {
                    MailOutcome.PickupFallbackNeeded(parsed.keylessRecipients, parsed.error)
                } else {
                    MailOutcome.BadRequest(rawBody.ifBlank { "Conflicting request" })
                }
            }
        }
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/mail/ app/src/test/java/com/urlxl/mail/mail/
git commit -m "feat(pgp): map the keyless-recipient 409 to its own outcome"
```

---

### Task 3: `PgpComposeState` — which controls exist

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/PgpComposeState.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/PgpComposeStateTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `data class PgpComposeState(val canEncrypt: Boolean, val canSign: Boolean, val handoffToWebmail: Boolean)` and `fun pgpComposeStateOf(hasIdentity: Boolean?, protection: String?): PgpComposeState`

This mirrors `PgpMessageState.kt` exactly: a pure function so the rule is unit-testable and the Activity only picks views.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.urlxl.mail.pgp

import kotlin.test.assertEquals
import org.junit.Test

class PgpComposeStateTest {

    @Test
    fun serverCustodyWithIdentity_offersBoth() {
        val state = pgpComposeStateOf(hasIdentity = true, protection = "server")
        assertEquals(PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false), state)
    }

    /** Encrypting needs only the recipients' public keys, so it works with no
     *  sender identity at all. Signing is the one that needs a key. Gating both
     *  on hasIdentity would deny encryption to an account that never made one. */
    @Test
    fun serverCustodyWithoutIdentity_stillOffersEncrypt() {
        val state = pgpComposeStateOf(hasIdentity = false, protection = "server")
        assertEquals(PgpComposeState(canEncrypt = true, canSign = false, handoffToWebmail = false), state)
    }

    @Test
    fun clientCustody_offersNeitherAndHandsOff() {
        val state = pgpComposeStateOf(hasIdentity = true, protection = "client")
        assertEquals(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true), state)
    }

    /** Couldn't check is not "no". Hide everything rather than guessing a
     *  custody mode — guessing "server" would offer an encrypt toggle that
     *  409s, and guessing "client" would send people to webmail needlessly. */
    @Test
    fun unknownBootstrap_hidesEverything() {
        val state = pgpComposeStateOf(hasIdentity = null, protection = null)
        assertEquals(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false), state)
    }

    @Test
    fun accountWithNoPgpAtAll_hidesEverythingButIsNotAHandoff() {
        val state = pgpComposeStateOf(hasIdentity = false, protection = "")
        assertEquals(PgpComposeState(canEncrypt = true, canSign = false, handoffToWebmail = false), state)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*PgpComposeStateTest*"`
Expected: FAIL — unresolved reference.

- [ ] **Step 3: Write the implementation**

```kotlin
package com.urlxl.mail.pgp

/**
 * Which PGP controls the compose screen offers, as a pure function of what
 * GET /api/pgp/bootstrap said.
 *
 * Kept out of the Activity for the same reason as [PgpMessageState]: the rule
 * is testable without instrumentation, and the view only picks widgets.
 */
data class PgpComposeState(
    val canEncrypt: Boolean,
    val canSign: Boolean,
    /** Show "Continue in webmail" instead of the toggles: this account's key is
     *  end-to-end protected, so the server cannot encrypt on its behalf and
     *  this app holds no private key. */
    val handoffToWebmail: Boolean,
)

/**
 * [hasIdentity] and [protection] are null when bootstrap could not be reached.
 * Unknown hides everything: guessing "server" offers a toggle that 409s, and
 * guessing "client" sends people to webmail for no reason.
 *
 * Note that canEncrypt does not depend on [hasIdentity]. Encryption uses the
 * recipients' public keys; only signing needs the sender's own key.
 */
fun pgpComposeStateOf(hasIdentity: Boolean?, protection: String?): PgpComposeState = when {
    protection == null -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
    protection == "client" -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true)
    else -> PgpComposeState(canEncrypt = true, canSign = hasIdentity == true, handoffToWebmail = false)
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*PgpComposeStateTest*"`
Expected: PASS (all five).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/PgpComposeState.kt app/src/test/java/com/urlxl/mail/pgp/PgpComposeStateTest.kt
git commit -m "feat(pgp): derive compose controls from the bootstrap custody mode"
```

---

### Task 4: `PgpBootstrapClient`

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/PgpBootstrapClient.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/PgpBootstrapClientTest.kt`

**Interfaces:**
- Consumes: `pgpComposeStateOf` (Task 3)
- Produces: `sealed class PgpBootstrapResult { data class Success(val hasIdentity: Boolean, val protection: String); object NotPaired; data class Failed(val message: String) }` and `suspend fun PgpBootstrapClient.fetch(serverUrl, deviceId, deviceSecret): PgpBootstrapResult`

Model this on `pgp/PgpQrClient.kt` — same device-header auth (`pairingAuthHeaders`), same pinned call factory (`pinnedPairingCallFactory`), same `executeSync` usage. Read that file before writing this one; matching it is more important than any structure suggested here.

- [ ] **Step 1: Write the failing test**

```kotlin
@Test
fun parsesProtectionAndIdentity() {
    val client = PgpBootstrapClient(callFactory = cannedCallFactory(
        code = 200,
        body = """{"hasIdentity":true,"protection":"client","unlockRequired":true}""",
    ))

    val result = runBlocking { client.fetch("https://relay.example.com", "device-1", "secret-1") }

    assertEquals(PgpBootstrapResult.Success(hasIdentity = true, protection = "client"), result)
}

/** A failed bootstrap must be distinguishable from a successful "no identity",
 *  or the compose screen cannot honor the couldn't-check-is-not-no rule. */
@Test
fun networkFailure_isFailedNotAnEmptySuccess() {
    val client = PgpBootstrapClient(callFactory = cannedCallFactory(code = 503, body = "unavailable"))

    val result = runBlocking { client.fetch("https://relay.example.com", "device-1", "secret-1") }

    assertTrue(result is PgpBootstrapResult.Failed)
}

/** Unknown fields must not break parsing: bootstrap carries signerPublicKeys,
 *  payloadEndpoint and more that this client has no use for. */
@Test
fun ignoresUnknownFields() {
    val client = PgpBootstrapClient(callFactory = cannedCallFactory(
        code = 200,
        body = """{"hasIdentity":false,"protection":"server","signerPublicKeys":[],"payloadEndpoint":"/x"}""",
    ))

    val result = runBlocking { client.fetch("https://relay.example.com", "device-1", "secret-1") }

    assertEquals(PgpBootstrapResult.Success(hasIdentity = false, protection = "server"), result)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*PgpBootstrapClientTest*"`
Expected: FAIL — unresolved.

- [ ] **Step 3: Implement**

Follow `PgpQrClient.kt`'s shape. The response DTO needs `ignoreUnknownKeys = true` on its `Json` instance — bootstrap returns considerably more than this client reads (see the field table in `kypost-server/docs/E2E_PGP.md:220-234`).

Delete `pgp/PgpIdentityStatus.kt` and `PgpIdentityStatusTest.kt` **only if** `grep -rn "hasPgpIdentity\|pgpIdentityFromMintResult" app/src` shows no remaining callers after this work. That file exists solely because `/api/pgp/identity` is session-only; bootstrap answers the same question properly. If `PgpKeyActivity` still uses it, leave it — removing it is not this plan's job.

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*PgpBootstrapClientTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/ app/src/test/java/com/urlxl/mail/pgp/
git commit -m "feat(pgp): fetch custody mode from /api/pgp/bootstrap"
```

---

### Task 5: `RecipientKeyClient`

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/RecipientKeyClient.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/RecipientKeyClientTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `suspend fun check(serverUrl, deviceId, deviceSecret, addresses: List<String>): RecipientKeyResult`, where `RecipientKeyResult` is `Success(val keyless: List<String>)` or `Failed(val message: String)`

**Endpoint: `POST /api/pgp/recipients/check`, not `resolve`.** `/api/pgp/recipients/resolve` is device-reachable but refuses with 409 for any account that is not client-protected (`pgp_resolve_handler.go:44-48`) — it exists to hand real public keys to a browser doing its own encryption, which is precisely the account type this app does *not* build encrypted send for. `check` answers the yes/no question and needs the server plan's Task 7 to reach device auth.

Request: `{"addresses": ["a@b.c", ...]}`. Response: a `results` array of `{address, hasKey, revoked, expired, tier}` (`pgp_keyserver.go:129-135`). "Keyless" means `hasKey == false` — the handler already folds revoked and expired into it (`pgp_keyserver.go:143` sets `HasKey` from `ks.Usable()`), so do not re-derive it from the other flags.

Only the keyless list is kept. Tiers exist for the web UI's per-recipient badges; this app has no use for them, so do not model them.

**Expect false positives.** `check` reads only pinned contact keys, while the send path also runs WKD/keyserver discovery, so it can report a recipient as keyless who turns out to have a key. Over-warning is the safe direction and the server's 409 is the real gate.

- [ ] **Step 1: Write the failing test**

```kotlin
@Test
fun reportsRecipientsWithNoUsableKey() {
    val client = RecipientKeyClient(callFactory = cannedCallFactory(
        code = 200,
        body = """{"results":[
            {"address":"bob@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"carol@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}""",
    ))

    val result = runBlocking {
        client.check("https://relay.example.com", "d", "s", listOf("bob@example.com", "carol@example.com"))
    }

    assertEquals(listOf("carol@example.com"), (result as RecipientKeyResult.Success).keyless)
}

/** hasKey is already false for a revoked or expired key (the handler sets it
 *  from ks.Usable()), so a revoked contact counts as keyless without the client
 *  re-deriving anything from the revoked/expired flags. */
@Test
fun revokedKeyCountsAsKeyless() {
    val client = RecipientKeyClient(callFactory = cannedCallFactory(
        code = 200,
        body = """{"results":[
            {"address":"dave@example.com","hasKey":false,"revoked":true,"expired":false,"tier":"none"}
        ]}""",
    ))

    val result = runBlocking { client.check("https://relay.example.com", "d", "s", listOf("dave@example.com")) }

    assertEquals(listOf("dave@example.com"), (result as RecipientKeyResult.Success).keyless)
}

/** A failed preflight must not read as "everyone has a key" — that would let
 *  the send proceed believing no fallback is involved. */
@Test
fun failureIsDistinctFromNoKeylessRecipients() {
    val client = RecipientKeyClient(callFactory = cannedCallFactory(code = 500, body = "boom"))

    val result = runBlocking { client.check("https://relay.example.com", "d", "s", listOf("bob@example.com")) }

    assertTrue(result is RecipientKeyResult.Failed)
}
```

Confirm the `results` wrapper key against the handler's final `writeJSON` call in `pgp_keyserver.go` before writing the DTO — the field list above is from the struct definition, the wrapper name is set at the response site.

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RecipientKeyClientTest*"`
Expected: FAIL — unresolved.

- [ ] **Step 3: Implement**, following `PgpQrClient.kt` for auth and error handling.

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RecipientKeyClientTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/RecipientKeyClient.kt app/src/test/java/com/urlxl/mail/pgp/RecipientKeyClientTest.kt
git commit -m "feat(pgp): resolve recipient keys before an encrypted send"
```

---

### Task 6: Webmail Drafts deep link

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt`
- Modify: `app/src/test/java/com/urlxl/mail/pgp/WebmailDeepLinkTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `fun webmailDraftsUrl(serverUrl: String): String?`

- [ ] **Step 1: Write the failing test**

```kotlin
@Test
fun draftsUrl_pointsAtTheDraftsMailbox() {
    assertEquals(
        "https://relay.example.com/read?mailbox=Drafts",
        webmailDraftsUrl("https://relay.example.com"),
    )
}

@Test
fun draftsUrl_toleratesATrailingSlash() {
    assertEquals(
        "https://relay.example.com/read?mailbox=Drafts",
        webmailDraftsUrl("https://relay.example.com/"),
    )
}

/** Same contract as webmailMessageUrl: an unusable server URL renders as no
 *  button rather than a dead one. */
@Test
fun draftsUrl_isNullForAnUnusableServerUrl() {
    assertNull(webmailDraftsUrl("not a url"))
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*WebmailDeepLinkTest*"`
Expected: FAIL — unresolved.

- [ ] **Step 3: Implement**

```kotlin
/**
 * The webmail URL that opens the Drafts mailbox, used after handing a
 * client-custody composition off to the browser.
 *
 * It targets the mailbox rather than one specific draft because
 * POST /api/mail/draft answers with a bare {ok: true} and no UID — there is
 * nothing to deep-link to. The draft the user just saved is the newest one.
 *
 * Unlike INBOX in [webmailMessageUrl], Drafts is passed explicitly: an absent
 * mailbox means INBOX to ReadPage.
 */
fun webmailDraftsUrl(serverUrl: String): String? {
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder().addQueryParameter("mailbox", "Drafts").build().toString()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*WebmailDeepLinkTest*"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/WebmailDeepLink.kt app/src/test/java/com/urlxl/mail/pgp/WebmailDeepLinkTest.kt
git commit -m "feat(pgp): add the webmail Drafts deep link"
```

---

### Task 7: Wire it into compose

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/ComposePgpController.kt`
- Modify: `app/src/main/java/com/urlxl/mail/ComposeActivity.kt:311-349` (`sendEmail`), `:184-212` (`applyToolbarChipsTheme`)
- Modify: `app/src/main/res/layout/activity_compose.xml`, `app/src/main/res/values/strings.xml`
- Create: `app/src/test/java/com/urlxl/mail/ComposePgpControllerTest.kt`

**Interfaces:**
- Consumes: everything from Tasks 1-6
- Produces: a top-level `fun sendDecision(keyless: List<String>, confirmed: Boolean): SendDecision` (free function, so it is testable with no controller instance), plus `ComposePgpController` with `suspend fun prepare(): PgpComposeState` and `suspend fun preflight(addresses: List<String>): List<String>` (the keyless list; empty on failure)

`ComposeActivity` is already 364 dense lines. The decision logic lives in the controller, unit-tested without a `Context`; the Activity renders and dispatches only.

- [ ] **Step 1: Write the failing test for the decision logic**

```kotlin
class ComposePgpControllerTest {

    @Test
    fun noKeylessRecipients_sendsWithoutPrompting() {
        assertEquals(SendDecision.Send(allowPickupFallback = false), sendDecision(emptyList(), confirmed = false))
    }

    @Test
    fun keylessRecipients_promptFirst() {
        assertEquals(SendDecision.Confirm(listOf("carol@example.com")), sendDecision(listOf("carol@example.com"), confirmed = false))
    }

    /** Only after the user has seen the names and what the fallback costs. */
    @Test
    fun keylessRecipientsConfirmed_sendsWithTheOptIn() {
        assertEquals(SendDecision.Send(allowPickupFallback = true), sendDecision(listOf("carol@example.com"), confirmed = true))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*ComposePgpControllerTest*"`
Expected: FAIL — unresolved.

- [ ] **Step 3: Implement the controller**

```kotlin
sealed class SendDecision {
    data class Send(val allowPickupFallback: Boolean) : SendDecision()
    data class Confirm(val keylessRecipients: List<String>) : SendDecision()
}

/**
 * Whether this send may go out as-is.
 *
 * A failed preflight yields an empty keyless list and therefore Send(false) —
 * deliberately. Not blocking on a failed lookup keeps a flaky network from
 * making mail unsendable, and false means the server's own 409 is still the
 * gate, so a failed preflight can never be the reason the fallback gets used.
 */
fun sendDecision(keyless: List<String>, confirmed: Boolean): SendDecision = when {
    keyless.isEmpty() -> SendDecision.Send(allowPickupFallback = false)
    confirmed -> SendDecision.Send(allowPickupFallback = true)
    else -> SendDecision.Confirm(keyless)
}
```

Then the `ComposePgpController` class holding `PgpBootstrapClient` and `RecipientKeyClient`, exposing `prepare()` and `preflight()`.

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*ComposePgpControllerTest*"`
Expected: PASS.

- [ ] **Step 5: Wire the Activity**

- On `onCreate`, call `prepare()` and apply the resulting `PgpComposeState`: show Encrypt and/or Sign chips, or the "Continue in webmail" action, or neither.
- Debounce recipient-field changes while Encrypt is on; call `preflight()`; keep the keyless list.
- In `sendEmail()` (`:311`), consult `sendDecision`. On `Confirm`, show an `AlertDialog` naming the addresses; on confirm, re-send with `allowPickupFallback = true`.
- Handle the two new outcomes from `MailRepository.send`: `PickupFallbackNeeded` opens the same dialog (a recipient typed after the last debounce lands here); `ClientSideNeeded` offers the handoff.
- Handoff: `saveDraft`, and **only if it succeeds**, `startActivity(Intent(ACTION_VIEW, Uri.parse(webmailDraftsUrl(serverUrl))))`. If the draft save fails, show the error and keep the compose screen — opening a browser onto a draft that is not there loses the user's message.
- Display `MailSendOutcome.warning` when non-empty. A 200 is not unqualified success.

All user-facing copy goes in `strings.xml`. The confirm dialog must name the addresses and say: stored on the server in plaintext for 7 days, the link travels as ordinary unencrypted mail, and anyone holding the link can read it once.

- [ ] **Step 6: Build and run the whole suite**

Run: `./gradlew assembleDebug testDebugUnitTest`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/ app/src/main/res/ app/src/test/java/com/urlxl/mail/
git commit -m "feat(pgp): offer encrypted send on mobile for server-custody accounts"
```

---

## Manual verification

Against a real paired server — none of the above touches a real IMAP or SMTP server:

- [ ] Server-custody account, recipient with a key in Contacts → arrives encrypted.
- [ ] Server-custody, one keyless recipient → dialog names them; cancel keeps the draft intact; confirm delivers and the keyless recipient gets a working link.
- [ ] Server-custody account with no PGP identity → Encrypt is offered, Sign is not.
- [ ] Client-custody account → toggles replaced by "Continue in webmail"; tapping it saves the draft and opens the system browser at Drafts, with the composition intact.
- [ ] Airplane mode at compose open → no PGP controls appear, plain send still works.
