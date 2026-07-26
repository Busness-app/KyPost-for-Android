# Client Encrypted Send Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `server`-custody account send signed and encrypted mail natively from this app, confirm the keyless-recipient pickup fallback honestly, and hand a `client`-custody account off to webmail instead of failing.

**Architecture:** The app does no OpenPGP and holds no private key. It sets `sign`/`encrypt`/`allowPickupFallback` on `POST /api/mail/send` and the server does the crypto. Which custody mode is in force comes from `GET /api/pgp/bootstrap`; which recipients lack a contact key comes from `POST /api/pgp/recipients/check`. Both new HTTP clients follow `pgp/PgpQrClient.kt` exactly (device-header auth, injectable `Call.Factory`, status-code-to-sealed-result mapping). The decision rules live in pure functions and a controller so they are unit-testable without a `Context`; `ComposeActivity` renders and dispatches only.

**Tech Stack:** Kotlin, OkHttp 5.2.1, kotlinx.serialization, JUnit4 + `kotlin.test` assertions, hand-rolled fakes (no mocking framework, no MockWebServer — see `app/src/test/java/com/urlxl/mail/pgp/PgpQrClientTest.kt:22-68`).

**Spec:** `Client_Encrypted_Send.md` (repo root, written 2026-07-26).

**Supersedes:** `docs/superpowers/plans/2026-07-25-mobile-encrypted-send.md`. That plan was written before the spec and differs on two substantive points — it gated Encrypt independently of `hasIdentity`, and it used the preflight to drive a *blocking* pre-send dialog. This plan follows the spec on both. Do not execute both plans.

**Depends on:** `kypost-server` branch `feat/mobile-encrypted-send`, which is **not merged and not deployed**. Tasks 1-7 are fully unit-testable today; only "Manual verification" needs the server. A 404 or an ignored field is that branch missing, not a client bug.

## Global Constraints

- The app holds **no private key** and does **no OpenPGP**. If a task seems to need Bouncy Castle, it is the wrong task.
- **Never call** `POST /api/pgp/recipients/resolve` (409s for every non-`client` account), `POST /api/pgp/pickup`, or `POST /api/mail/send-pgp`. Use `check` for the preflight.
- **Do not build** a remembered "always allow pickup fallback" preference. The opt-in is per-message; it must reset on every compose.
- Only the two 409 shapes and the 200 are JSON. **Every other status returns plain text** — never run a JSON decoder over a 400/502/503 body.
- Discriminate the two 409s **by field** (`clientSideNeeded` vs `keylessRecipients`), never by status code or error prose.
- `allowPickupFallback` is `true` only after the user confirms the dialog naming the addresses. Never default it on.
- The re-send after confirmation must reuse the **same in-memory `MailDraft`** with only `allowPickupFallback` flipped. Do not re-export the editor HTML, do not re-encode attachments, do not re-run the preflight — a rebuild risks a subtly different message.
- Preflight is a **lower bound, not a prediction**: `check` reads contacts only, while the send path also runs WKD/keyserver discovery. Word it "no key on file", never "this will be sent as a plaintext link".
- The confirmation dialog copy is **part of the contract** (spec § "Confirmation dialog copy"). Name the addresses explicitly; never summarize as "some recipients". Softening the seven-days-plaintext sentence defeats the opt-in.
- The webmail handoff goes to the **system** as an `ACTION_VIEW` https intent. Never an in-app WebView — it shares no session and would put an account-password field inside this app.
- All user-facing copy goes in `app/src/main/res/values/strings.xml`.
- Test style: hand-rolled fakes, `kotlin.test` assertions with `org.junit.Test`, `runBlocking` for suspend functions.

## File Structure

| File | Responsibility |
|---|---|
| `mail/MailSource.kt` | `MailDraft` PGP flags; `MailOutcome.PickupFallbackNeeded`; its `userFacingMessage` branch |
| `mail/RelayModels.kt` | `RelayMailRequestDto` flags; `RelayPickupFallbackDto` |
| `mail/RelayMailSource.kt` | send-only wire mapping; 409 discrimination; 502 body pass-through |
| `pgp/PgpComposeState.kt` (new) | Pure: bootstrap answer → which compose controls exist |
| `pgp/PgpBootstrapClient.kt` (new) | `GET /api/pgp/bootstrap` |
| `pgp/RecipientKeyClient.kt` (new) | `POST /api/pgp/recipients/check` |
| `pgp/WebmailDeepLink.kt` | gains `webmailDraftsUrl` |
| `ComposePgpController.kt` (new) | Session bootstrap cache, address splitting, preflight — keeps `ComposeActivity` a view |
| `ComposeActivity.kt` | Toggles, inline warning, both 409 paths, handoff, re-send |
| `res/layout/activity_compose.xml` | Encrypt/Sign chips, webmail chip, keyless-warning callout |
| `res/values/strings.xml` | All copy, including the contract dialog wording |

**Already implemented — do not redo:** read-side `pgp/PgpMessageState.kt`; `webmailMessageUrl`; `saveDraft`; the `clientSideNeeded` 409 mapping (`RelayMailSource.kt:24-26,303-307`); `warning` parsing *and* display (`ComposeActivity.kt:332-338` already shows it as a non-blocking notice — the spec asked this be verified; it is correct, no change needed). `pgp/PgpIdentityStatus.kt` stays: `hasPgpIdentity` still has three callers in the contacts screens.

---

### Task 1: Send the PGP flags on the wire

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/mail/MailSource.kt:88-96` (`MailDraft`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayModels.kt:106-115` (`RelayMailRequestDto`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayMailSource.kt:208` (`sendMail`) and `:366` (`toWireDto`)
- Test: `app/src/test/java/com/urlxl/mail/mail/RelayMailSourceTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `MailDraft(… , sign: Boolean = false, encrypt: Boolean = false, allowPickupFallback: Boolean = false)`; private `fun MailDraft.toSendWireDto(): RelayMailRequestDto`

**Why a second mapper:** `toWireDto()` is called by *both* `sendMail` (`:208`) and `saveDraft` (`:198`). Drafts have no crypto semantics — the server's draft handler ignores these fields — so putting them in the shared mapper would make `saveDraft` claim a choice the user has not made at draft-save time. This also matters for the Task 8 handoff, which saves a draft from a composition whose Encrypt toggle was on.

- [ ] **Step 1: Write the failing tests**

Append inside `class RelayMailSourceTest`. `FakeCallFactory` at `:51` records requests but not bodies, so add a body-recording fake next to it, following `MfaResponseClientTest.kt:21-32`:

```kotlin
/** Records request bodies as well as requests — [FakeCallFactory] keeps only the latter, and the
 *  PGP send flags are body fields. Mirrors MfaResponseClientTest's body-capturing fake. */
private class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        val buffer = okio.Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return FakeCall(request, responder(request))
    }
}
```

`FakeCall` is already private-in-file at `RelayMailSourceTest.kt:74`; reuse it rather than adding another.

```kotlin
    @Test
    fun sendMail_putsPgpFlagsOnTheWire() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.sendMail(
            MailDraft(
                to = "bob@example.com", subject = "hi", body = "hello",
                sign = true, encrypt = true, allowPickupFallback = true,
            ),
        )

        val sent = callFactory.bodies.single()
        assertTrue("expected sign in $sent", sent.contains("\"sign\":true"))
        assertTrue("expected encrypt in $sent", sent.contains("\"encrypt\":true"))
        assertTrue("expected allowPickupFallback in $sent", sent.contains("\"allowPickupFallback\":true"))
    }

    /** Drafts carry no crypto semantics — the server's draft handler ignores these fields — so
     *  sending them would claim a choice the user did not make at draft-save time. The webmail
     *  handoff saves a draft from a composition whose Encrypt toggle was on, so this is a live
     *  path, not a hypothetical. */
    @Test
    fun saveDraft_omitsPgpFlags() {
        val callFactory = BodyRecordingCallFactory { request -> jsonResponse(request, """{"ok":true}""") }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.saveDraft(
            MailDraft(to = "bob@example.com", subject = "hi", body = "hello", encrypt = true, sign = true),
        )

        val sent = callFactory.bodies.single()
        assertTrue("expected no encrypt in $sent", !sent.contains("encrypt"))
        assertTrue("expected no sign in $sent", !sent.contains("\"sign\""))
        assertTrue("expected no allowPickupFallback in $sent", !sent.contains("allowPickupFallback"))
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: FAIL — `MailDraft` has no `sign` parameter.

- [ ] **Step 3: Add the fields and the send-only mapper**

`MailSource.kt`, appended inside `MailDraft` after `attachments`:

```kotlin
    /** Server-side PGP signing. Requires the account to have a PGP identity; the relay answers
     *  400 (plain text) if asked to sign without one. */
    val sign: Boolean = false,
    /** Server-side PGP encryption. */
    val encrypt: Boolean = false,
    /** Opt in to the one-time pickup link for recipients with no usable key. Meaningful only when
     *  [encrypt] is true, and only ever set after the user confirmed the dialog naming them: the
     *  fallback stores this message's plaintext on the server, unencrypted, for up to seven days.
     *  Per-message by design — never persisted as a preference. */
    val allowPickupFallback: Boolean = false,
```

`RelayModels.kt`, appended inside `RelayMailRequestDto` after `attachments`. All three default false, so the draft DTO — which never sets them — stays wire-identical to today:

```kotlin
    /** Only /api/mail/send reads these three; /api/mail/draft ignores them, which is why
     *  [com.urlxl.mail.mail.MailDraft] maps to this DTO through two different functions. */
    val sign: Boolean = false,
    val encrypt: Boolean = false,
    val allowPickupFallback: Boolean = false,
```

`RelayMailSource.kt`, immediately after the existing `toWireDto` (ends `:375`):

```kotlin
/** Send-only mapping. [toWireDto] stays flagless because /api/mail/draft ignores these fields —
 *  see [MailDraft.allowPickupFallback]. */
private fun MailDraft.toSendWireDto(): RelayMailRequestDto =
    toWireDto().copy(sign = sign, encrypt = encrypt, allowPickupFallback = allowPickupFallback)
```

Change `sendMail`'s body line (`:208`) from `json.encodeToString(draft.toWireDto())` to `json.encodeToString(draft.toSendWireDto())`. Leave `saveDraft` (`:198`) on `toWireDto()`.

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: PASS, including the pre-existing tests.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/mail/ app/src/test/java/com/urlxl/mail/mail/
git commit -m "feat(pgp): send sign/encrypt/allowPickupFallback on the relay send"
```

---

### Task 2: Tell the two 409s apart

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/mail/MailSource.kt` (`MailOutcome`, `userFacingMessage`)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayModels.kt` (new response DTO)
- Modify: `app/src/main/java/com/urlxl/mail/mail/RelayMailSource.kt:303-307` (the 409 branch), `:308` (502)
- Test: `app/src/test/java/com/urlxl/mail/mail/RelayMailSourceTest.kt`

**Interfaces:**
- Consumes: Task 1
- Produces: `MailOutcome.PickupFallbackNeeded(val keylessRecipients: List<String>, val message: String)`; `RelayPickupFallbackDto`

**Why this is not a live regression today:** `mapErrorCode` currently substring-tests for `clientSideNeeded` and otherwise returns `BadRequest(rawBody)`, which would show the user raw JSON. The app never sets `encrypt`, so it never reaches the keyless gate. Task 1 just made it reachable.

**Note on substring vs decode:** the existing `CLIENT_SIDE_NEEDED_MARKER` check stays a substring test — it is deliberately tolerant of a body that may not be JSON. The new branch needs the address list, so it decodes. Both are field-based, which is what the contract specifies.

**Note on `encodeDefaults`:** `RelayMailSource`'s `Json` leaves `encodeDefaults` at its default of false, so a `false` flag is **omitted from the body**, not sent as `false`. That is correct — the spec says all three fields are optional and default to false server-side. Do not turn `encodeDefaults` on to "fix" it; that would change every other request this class sends.

- [ ] **Step 1: Write the failing tests**

These reuse `BodyRecordingCallFactory` from Task 1. Add `import kotlinx.serialization.json.Json` to the test file for the re-send comparison.

```kotlin
    /** The keyless-recipient refusal. Nothing was delivered — the 409 happens before any SMTP —
     *  so re-sending with allowPickupFallback cannot duplicate the message. */
    @Test
    fun send409WithKeylessRecipients_mapsToPickupFallbackNeeded() {
        val body = """{"error":"some recipients have no usable PGP key","keylessRecipients":["carol@example.com"],"pickupFallbackAvailable":true}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "carol@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected PickupFallbackNeeded, got $outcome", outcome is MailOutcome.PickupFallbackNeeded)
        assertEquals(
            listOf("carol@example.com"),
            (outcome as MailOutcome.PickupFallbackNeeded).keylessRecipients,
        )
    }

    /** Both refusals are 409 and are told apart by which field is present. A client-custody
     *  account must keep resolving to ClientSideNeeded — offering it a pickup-link dialog would
     *  answer a question it never got to ask, and no re-send from this device can fix it. */
    @Test
    fun send409WithBothMarkers_prefersClientSideNeeded() {
        val body = """{"error":"e2e","clientSideNeeded":true,"keylessRecipients":["carol@example.com"]}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "carol@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected ClientSideNeeded, got $outcome", outcome is MailOutcome.ClientSideNeeded)
    }

    /** An unrecognized 409 must not become a pickup prompt, and must not show the user raw JSON. */
    @Test
    fun send409WithNeitherField_isGenericBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, """{"error":"conflict"}""", code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
        assertTrue(
            "raw JSON must not reach the user: $outcome",
            !(outcome as MailOutcome.BadRequest).message.contains("{"),
        )
    }

    /** A 409 whose keylessRecipients is present but empty carries no addresses to name in the
     *  dialog, so it cannot drive the confirmation flow. */
    @Test
    fun send409WithEmptyKeylessList_isGenericBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory {
                request -> jsonResponse(request, """{"error":"x","keylessRecipients":[]}""", code = 409)
            },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
    }

    /** 502 bodies are plain text and say which of two things happened — SMTP failed, or every
     *  pickup link failed to deliver. Both mean nothing was sent, and the second is invisible
     *  under a fixed "Upstream IMAP/SMTP failure" string. */
    @Test
    fun send502_carriesTheServersPlainTextReason() {
        val reason = "failed to deliver a pickup link to any recipient; nothing was sent"
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, reason, code = 502) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertEquals(reason, (outcome as MailOutcome.UpstreamFailure).message)
    }

    /** The confirmed re-send must differ from the refused attempt in exactly one field. The
     *  Activity achieves this by holding the same MailDraft and calling .copy() (Task 8); this
     *  pins the wire-level property that makes it safe — a rebuilt message could differ subtly,
     *  and the recipients who *do* have keys would get something other than what was refused. */
    @Test
    fun resendWithFallback_differsOnlyInAllowPickupFallback() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )
        val draft = MailDraft(
            to = "carol@example.com", cc = "bob@example.com", subject = "hi", body = "<p>hello</p>",
            mode = "html", encrypt = true, sign = true,
        )

        source.sendMail(draft)
        source.sendMail(draft.copy(allowPickupFallback = true))

        // Compared structurally, not as strings: kotlinx.serialization's encodeDefaults is false,
        // so the refused attempt omits allowPickupFallback entirely rather than sending false.
        val wireJson = Json { ignoreUnknownKeys = true }
        val first = wireJson.decodeFromString<RelayMailRequestDto>(callFactory.bodies[0])
        val second = wireJson.decodeFromString<RelayMailRequestDto>(callFactory.bodies[1])
        assertEquals(false, first.allowPickupFallback)
        assertEquals(true, second.allowPickupFallback)
        assertEquals(first, second.copy(allowPickupFallback = false))
    }

    /** A 200 with a non-empty warning is a success with a notice — the message was sent. It must
     *  never map to a failure, which would invite a retry that duplicates the message. */
    @Test
    fun send200WithWarning_isSuccessCarryingTheWarning() {
        val body = """{"ok":true,"sentSaved":false,"warning":"failed to deliver a pickup link to 1 of 3 recipient(s)"}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        val sent = (outcome as MailOutcome.Success).value
        assertEquals("failed to deliver a pickup link to 1 of 3 recipient(s)", sent.warning)
        assertEquals(false, sent.sentSaved)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: FAIL — `MailOutcome.PickupFallbackNeeded` unresolved.

- [ ] **Step 3: Add the outcome, the DTO, and the branch**

`MailSource.kt`, in the `MailOutcome` sealed class after `ClientSideNeeded`:

```kotlin
    /** Relay 409 on /api/mail/send carrying `keylessRecipients` — one or more recipients have no
     *  usable PGP key, and the server refused rather than quietly falling back to a one-time link
     *  that stores this message's plaintext on the server for seven days. **Nothing was
     *  delivered:** the refusal happens before any SMTP, so re-sending the same draft with
     *  [MailDraft.allowPickupFallback] once the user has confirmed is safe and cannot duplicate. */
    data class PickupFallbackNeeded(
        val keylessRecipients: List<String>,
        val message: String,
    ) : MailOutcome<Nothing>()
```

In `userFacingMessage()` — a `when` over a sealed class, so omitting this will not compile. It is only a fallback: `ComposeActivity` shows the contract dialog instead of this string, and reaches it only if the dialog cannot be shown.

```kotlin
    is MailOutcome.PickupFallbackNeeded ->
        "No PGP key on file for ${keylessRecipients.joinToString(", ")} — nothing was sent."
```

`RelayModels.kt`, next to `RelaySendResponseDto`:

```kotlin
/** The 409 body /api/mail/send returns when recipients have no usable PGP key. Both PGP refusals
 *  are 409 and are told apart by which field is present, never by status or error prose — the
 *  prose is user-facing copy and may be reworded. */
@Serializable
data class RelayPickupFallbackDto(
    val error: String = "",
    val keylessRecipients: List<String> = emptyList(),
    val pickupFallbackAvailable: Boolean = false,
)
```

`RelayMailSource.kt`, replacing the 409 branch at `:303-307` and the 502 line at `:308`:

```kotlin
        // Two PGP refusals share this status. clientSideNeeded is checked first to match the
        // server's own precedence: a client-custody account cannot encrypt server-side at all, so
        // its keyless recipients are beside the point and a pickup dialog would be nonsense.
        409 -> when {
            rawBody.contains(CLIENT_SIDE_NEEDED_MARKER, ignoreCase = true) ->
                MailOutcome.ClientSideNeeded(rawBody)
            else -> {
                val parsed = runCatching { json.decodeFromString<RelayPickupFallbackDto>(rawBody) }.getOrNull()
                if (parsed != null && parsed.keylessRecipients.isNotEmpty()) {
                    MailOutcome.PickupFallbackNeeded(parsed.keylessRecipients, parsed.error)
                } else {
                    // Deliberately not rawBody: an unrecognized 409 body is JSON, and raw JSON in
                    // a toast is worse than a generic sentence.
                    MailOutcome.BadRequest("Conflicting request")
                }
            }
        }
        // Plain text, and it distinguishes "SMTP failed" from "every pickup link failed to
        // deliver; nothing was sent" — a distinction a fixed string throws away.
        502 -> MailOutcome.UpstreamFailure(rawBody.ifBlank { "Upstream IMAP/SMTP failure" })
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RelayMailSourceTest*"`
Expected: PASS. The pre-existing `send409WithoutMarker_staysBadRequest` still passes — it only asserts the outcome type.

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
- Produces: `data class PgpComposeState(val canEncrypt: Boolean, val canSign: Boolean, val handoffToWebmail: Boolean)`; `fun pgpComposeStateOf(hasIdentity: Boolean?, protection: String?): PgpComposeState`

Mirrors `PgpMessageState.kt`: a pure function, so the rule is unit-testable and the Activity only picks widgets.

**A note for anyone comparing this to the superseded plan:** that plan offered Encrypt without an identity, reasoning that encryption needs only the recipients' public keys. The spec says otherwise — `protection: ""` means "plaintext send only", and toggles appear when `hasIdentity` is true. Follow the spec. Gating both on `hasIdentity` is also the conservative direction: at worst an identity-less account misses a toggle it might have been allowed, which is a missing affordance rather than a send that 400s.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.urlxl.mail.pgp

import kotlin.test.assertEquals
import org.junit.Test

class PgpComposeStateTest {

    @Test
    fun serverCustodyWithIdentity_offersBoth() {
        assertEquals(
            PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = true, protection = "server"),
        )
    }

    /** No identity means plaintext send only (spec's custody table). No toggles, and not a
     *  handoff either — there is no key held anywhere to hand off to. */
    @Test
    fun noIdentity_offersNothingAndIsNotAHandoff() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = false, protection = ""),
        )
    }

    /** The key is unwrapped only in the browser, from a password this device never learns. */
    @Test
    fun clientCustody_offersNeitherAndHandsOff() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
            pgpComposeStateOf(hasIdentity = true, protection = "client"),
        )
    }

    /** Couldn't check is not "no". A null protection means bootstrap failed: hide everything
     *  rather than guessing. Guessing "server" would offer a toggle that 409s, and guessing
     *  "client" would send people to webmail for no reason. */
    @Test
    fun unknownBootstrap_hidesEverything() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = null, protection = null),
        )
    }

    /** An unrecognized protection value degrades to "not server" rather than being treated as
     *  server-custody — the spec's parse-permissively rule. */
    @Test
    fun unknownProtectionValue_degradesRatherThanGuessing() {
        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            pgpComposeStateOf(hasIdentity = true, protection = "quantum"),
        )
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*PgpComposeStateTest*"`
Expected: FAIL — unresolved reference `pgpComposeStateOf`.

- [ ] **Step 3: Write the implementation**

```kotlin
package com.urlxl.mail.pgp

/** The two `protection` values this app understands. Anything else degrades to "not server". */
private const val PROTECTION_SERVER = "server"
private const val PROTECTION_CLIENT = "client"

/**
 * Which PGP controls the compose screen offers, as a pure function of what
 * `GET /api/pgp/bootstrap` said.
 *
 * Kept out of the Activity for the same reason as [PgpMessageState]: the rule is testable without
 * instrumentation, and the view only picks widgets.
 */
data class PgpComposeState(
    val canEncrypt: Boolean,
    val canSign: Boolean,
    /** Show "Continue in webmail" instead of the toggles: this account's key is unwrapped only in
     *  the browser, from a password this device never learns, so neither the server nor this app
     *  can encrypt on its behalf. */
    val handoffToWebmail: Boolean,
)

/**
 * [hasIdentity] and [protection] are null when bootstrap could not be reached. Unknown hides
 * everything: guessing "server" offers a toggle that 409s, and guessing "client" sends people to
 * webmail for no reason.
 *
 * An unrecognized non-null [protection] is treated as "not server" — degrade, never guess.
 */
fun pgpComposeStateOf(hasIdentity: Boolean?, protection: String?): PgpComposeState = when {
    protection == null || hasIdentity != true ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
    protection == PROTECTION_CLIENT ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true)
    protection == PROTECTION_SERVER ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false)
    else -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
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
- Consumes: nothing
- Produces: `sealed class PgpBootstrapResult` with `Success(val hasIdentity: Boolean, val protection: String)` and `Failed(val message: String)`; `class PgpBootstrapClient(json, callFactory)` with `suspend fun fetch(serverUrl: String, deviceId: String, deviceSecret: String): PgpBootstrapResult`

Model on `pgp/PgpQrClient.kt` — same `pairingAuthHeaders`, same injectable `Call.Factory`, same `executeSync` inside `withContext(Dispatchers.IO)`. **Read that file before writing this one; matching it matters more than anything suggested here.**

Only two result cases, not PgpQrClient's five: every non-200 collapses to `Failed`, because the caller's only reaction to any of them is the same — hide the controls (couldn't-check-is-not-no). Do not model statuses the caller cannot act on differently.

- [ ] **Step 1: Write the failing test**

Copy the `FakeCallFactory` / `FakeCall` / `ThrowingCallFactory` / `ThrowingCall` / `response` block from `PgpQrClientTest.kt:22-68` into this new file — they are `private` to that file, and this repo duplicates them per test file rather than sharing a fixture.

```kotlin
class PgpBootstrapClientTest {

    @Test
    fun parsesProtectionAndIdentity() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"hasIdentity":true,"protection":"client"}""", 200)
        }
        val client = PgpBootstrapClient(callFactory = callFactory)

        val result = client.fetch("https://relay.example.com/", "device-1", "secret-1")

        assertEquals(PgpBootstrapResult.Success(hasIdentity = true, protection = "client"), result)
        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/bootstrap", sent.url.toString())
        assertEquals("GET", sent.method)
        assertEquals("device-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /** Bootstrap carries wrappedPrivateKey, unlockRequired, signerPublicKeys, payloadEndpoint and
     *  more, all of which exist for the browser. Unknown fields must not break parsing. */
    @Test
    fun ignoresTheBrowsersFields() = runBlocking {
        val body = """{"hasIdentity":false,"protection":"server","wrappedPrivateKey":"x","unlockRequired":true,"signerPublicKeys":[],"payloadEndpoint":"/x"}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(PgpBootstrapResult.Success(hasIdentity = false, protection = "server"), result)
    }

    /** A failed bootstrap must be distinguishable from a successful "no identity", or the compose
     *  screen cannot honor couldn't-check-is-not-no. */
    @Test
    fun httpFailure_isFailedNotAnEmptySuccess() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "unavailable", 503) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    /** 503 and 401 bodies are plain text; a decoder run over them must not surface as a parse
     *  error, and a network throw must not escape. */
    @Test
    fun networkThrow_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = ThrowingCallFactory(IOException("no route to host")))

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun malformedBody_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun unusableServerUrl_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*PgpBootstrapClientTest*"`
Expected: FAIL — unresolved reference `PgpBootstrapClient`.

- [ ] **Step 3: Implement**

```kotlin
package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request

/**
 * Outcome of `GET /api/pgp/bootstrap`.
 *
 * Two cases, not one per status code: the caller's response to *every* failure is identical — hide
 * the PGP controls, because couldn't-check is not "no" — so distinguishing 401 from 503 from a
 * malformed body would be a distinction nothing acts on.
 */
sealed class PgpBootstrapResult {
    /** [protection] is `"server"`, `"client"`, or `""` for an account with no identity. Passed
     *  through as the raw string; [pgpComposeStateOf] decides what it means, and treats anything
     *  unrecognized as "not server". */
    data class Success(val hasIdentity: Boolean, val protection: String) : PgpBootstrapResult()

    data class Failed(val message: String) : PgpBootstrapResult()
}

/** The two fields this app needs. The endpoint returns considerably more — wrappedPrivateKey,
 *  unlockRequired, signerPublicKeys, payloadEndpoint — all of it for the browser, none of it
 *  usable here, which is why the [Json] instance ignores unknown keys. */
@Serializable
private data class PgpBootstrapDto(
    val hasIdentity: Boolean = false,
    val protection: String = "",
)

/**
 * Reads the account's PGP key-custody mode. Pairing-authenticated with
 * X-Kypost-Device-Id/X-Kypost-Device-Secret exactly like every other relay call this app makes —
 * there is no mobile login and no session cookie. Kept parallel to [PgpQrClient].
 */
class PgpBootstrapClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Call.Factory (not the concrete OkHttpClient) so tests can inject a fake without a real
    // network call or a MockWebServer dependency; OkHttpClient itself satisfies this interface.
    private val callFactory: Call.Factory = pairingHttpClient(),
) {
    suspend fun fetch(serverUrl: String, deviceId: String, deviceSecret: String): PgpBootstrapResult {
        val url = "${serverUrl.trimEnd('/')}/api/pgp/bootstrap".toHttpUrlOrNull()
            ?: return PgpBootstrapResult.Failed("Server URL is not valid")
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return PgpBootstrapResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        // Only 200 is JSON here; every other status returns plain text, so no decoder runs over it.
        if (code != 200) return PgpBootstrapResult.Failed("PGP bootstrap failed ($code)")
        val parsed = runCatching { json.decodeFromString<PgpBootstrapDto>(rawBody) }.getOrNull()
            ?: return PgpBootstrapResult.Failed("Malformed PGP bootstrap response")
        return PgpBootstrapResult.Success(hasIdentity = parsed.hasIdentity, protection = parsed.protection)
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*PgpBootstrapClientTest*"`
Expected: PASS (all six).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/PgpBootstrapClient.kt app/src/test/java/com/urlxl/mail/pgp/PgpBootstrapClientTest.kt
git commit -m "feat(pgp): fetch key-custody mode from /api/pgp/bootstrap"
```

---

### Task 5: `RecipientKeyClient`

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/RecipientKeyClient.kt`
- Create: `app/src/test/java/com/urlxl/mail/pgp/RecipientKeyClientTest.kt`

**Interfaces:**
- Consumes: nothing
- Produces: `sealed class RecipientKeyResult` with `Success(val keyless: List<String>)` and `Failed(val message: String)`; `class RecipientKeyClient(json, callFactory)` with `suspend fun check(serverUrl: String, deviceId: String, deviceSecret: String, addresses: List<String>): RecipientKeyResult`

**`check`, never `resolve`.** `POST /api/pgp/recipients/resolve` looks right and is not: it returns recipients' actual public keys so a `client`-custody *browser* can encrypt locally, and it 409s for any account that is not client-protected — i.e. every account that can use this feature. An earlier server design draft got this backwards.

**Keyless means `hasKey == false`, full stop.** The server already folds revoked and expired into `hasKey`. Read `revoked`/`expired` only if you later want to explain *why*; never re-derive keyless from them, and never treat "revoked but present" as sendable. `tier` exists for the web UI's per-recipient badges — do not model it.

Only the keyless list survives into the result: it is the only thing the caller uses, and a richer return type would invite the UI to make promises the preflight cannot keep (trap 2).

- [ ] **Step 1: Write the failing test**

Copy the same fake block from `PgpQrClientTest.kt:22-68`, plus a body-recording factory following `MfaResponseClientTest.kt:21-32` (this endpoint is a POST and one test asserts the request body).

```kotlin
class RecipientKeyClientTest {

    @Test
    fun reportsOnlyRecipientsWithNoUsableKey() = runBlocking {
        val body = """{"results":[
            {"address":"bob@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"carol@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.check(
            "https://relay.example.com", "d", "s", listOf("bob@example.com", "carol@example.com"),
        )

        assertEquals(listOf("carol@example.com"), (result as RecipientKeyResult.Success).keyless)
    }

    /** hasKey is already false for a revoked or expired key — the server sets it from its own
     *  usability check — so a revoked contact counts as keyless without this client re-deriving
     *  anything from the revoked/expired flags. */
    @Test
    fun revokedKeyCountsAsKeyless() = runBlocking {
        val body = """{"results":[{"address":"dave@example.com","hasKey":false,"revoked":true,"expired":false,"tier":"none"}]}"""
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("dave@example.com"))

        assertEquals(listOf("dave@example.com"), (result as RecipientKeyResult.Success).keyless)
    }

    @Test
    fun postsTheAddressesAndAuthHeaders() = runBlocking {
        val callFactory = BodyRecordingCallFactory { request -> response(request, """{"results":[]}""", 200) }
        val client = RecipientKeyClient(callFactory = callFactory)

        client.check("https://relay.example.com/", "d", "s", listOf("bob@example.com"))

        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/recipients/check", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("d", sent.header(HEADER_DEVICE_ID))
        assertEquals("s", sent.header(HEADER_DEVICE_SECRET))
        assertEquals("""{"addresses":["bob@example.com"]}""", callFactory.bodies.single())
    }

    /** A failed preflight must not read as "everyone has a key" — that would let the compose
     *  screen imply an encrypted send when it has no idea. */
    @Test
    fun httpFailureIsDistinctFromNoKeylessRecipients() = runBlocking {
        val client = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "boom", 500) })

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    @Test
    fun networkThrowIsFailed() = runBlocking {
        val client = RecipientKeyClient(callFactory = ThrowingCallFactory(IOException("offline")))

        val result = client.check("https://relay.example.com", "d", "s", listOf("bob@example.com"))

        assertTrue("expected Failed, got $result", result is RecipientKeyResult.Failed)
    }

    /** No addresses to check is a local answer, not a round trip. */
    @Test
    fun emptyAddressListSkipsTheCall() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, """{"results":[]}""", 200) }
        val client = RecipientKeyClient(callFactory = callFactory)

        val result = client.check("https://relay.example.com", "d", "s", emptyList())

        assertEquals(emptyList(), (result as RecipientKeyResult.Success).keyless)
        assertTrue("expected no request, sent ${callFactory.requests}", callFactory.requests.isEmpty())
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*RecipientKeyClientTest*"`
Expected: FAIL — unresolved reference `RecipientKeyClient`.

- [ ] **Step 3: Implement**

```kotlin
package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

/**
 * Outcome of the recipient-key preflight.
 *
 * [Failed] is deliberately distinct from `Success(emptyList())`: a failed lookup must never read
 * as "everyone has a key", which would let the compose screen imply an encrypted send it knows
 * nothing about.
 */
sealed class RecipientKeyResult {
    /** [keyless] holds the addresses with no usable key **in the user's contacts**. This is a
     *  lower bound, not a prediction: the send path additionally runs WKD and keyserver discovery,
     *  so an address listed here may still be encrypted to successfully. Use it to warn, never to
     *  promise — the server's 409 is the real gate. */
    data class Success(val keyless: List<String>) : RecipientKeyResult()

    data class Failed(val message: String) : RecipientKeyResult()
}

@Serializable
private data class RecipientCheckRequestDto(val addresses: List<String>)

/** `revoked`, `expired` and `tier` are parsed but unused: the server already folds revoked and
 *  expired into [hasKey], and `tier` drives the web UI's per-recipient badges. They are declared
 *  only to document the shape — do not re-derive keyless from them. */
@Serializable
private data class RecipientKeyStatusDto(
    val address: String = "",
    val hasKey: Boolean = false,
    val revoked: Boolean = false,
    val expired: Boolean = false,
    val tier: String = "",
)

@Serializable
private data class RecipientCheckResponseDto(val results: List<RecipientKeyStatusDto> = emptyList())

/**
 * Asks which recipients have a usable PGP key, via `POST /api/pgp/recipients/check`.
 *
 * **Not `/api/pgp/recipients/resolve`.** That endpoint hands out recipients' actual public keys so
 * a client-custody *browser* can encrypt locally, and it refuses with 409 for any account that is
 * not client-protected — which is every account that can send encrypted from this app.
 *
 * Kept parallel to [PgpQrClient]: same device-header auth, same injectable [Call.Factory].
 */
class RecipientKeyClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val callFactory: Call.Factory = pairingHttpClient(),
) {
    suspend fun check(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        addresses: List<String>,
    ): RecipientKeyResult {
        if (addresses.isEmpty()) return RecipientKeyResult.Success(emptyList())
        val url = "${serverUrl.trimEnd('/')}/api/pgp/recipients/check".toHttpUrlOrNull()
            ?: return RecipientKeyResult.Failed("Server URL is not valid")
        val payload = json.encodeToString(RecipientCheckRequestDto(addresses))
        val request = Request.Builder().url(url).post(payload.toRequestBody(JSON_MEDIA_TYPE))
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return RecipientKeyResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        if (code != 200) return RecipientKeyResult.Failed("Recipient key check failed ($code)")
        val parsed = runCatching { json.decodeFromString<RecipientCheckResponseDto>(rawBody) }.getOrNull()
            ?: return RecipientKeyResult.Failed("Malformed recipient key response")
        return RecipientKeyResult.Success(parsed.results.filter { !it.hasKey }.map { it.address })
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*RecipientKeyClientTest*"`
Expected: PASS (all six).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/RecipientKeyClient.kt app/src/test/java/com/urlxl/mail/pgp/RecipientKeyClientTest.kt
git commit -m "feat(pgp): preflight recipient keys before an encrypted send"
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

Append to the existing `WebmailDeepLinkTest`:

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

    /** Same contract as webmailMessageUrl: an unusable server URL renders as no button rather
     *  than a dead one. */
    @Test
    fun draftsUrl_isNullForAnUnusableServerUrl() {
        assertNull(webmailDraftsUrl("not a url"))
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*WebmailDeepLinkTest*"`
Expected: FAIL — unresolved reference `webmailDraftsUrl`.

- [ ] **Step 3: Implement**

Append to `WebmailDeepLink.kt`:

```kotlin
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
fun webmailDraftsUrl(serverUrl: String): String? {
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder().addQueryParameter("mailbox", DRAFTS).build().toString()
}
```

and next to the existing `private const val INBOX`:

```kotlin
private const val DRAFTS = "Drafts"
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

### Task 7: `ComposePgpController` — session cache, address splitting, preflight

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/ComposePgpController.kt`
- Create: `app/src/test/java/com/urlxl/mail/ComposePgpControllerTest.kt`

**Interfaces:**
- Consumes: `pgpComposeStateOf` (Task 3), `PgpBootstrapClient`/`PgpBootstrapResult` (Task 4), `RecipientKeyClient`/`RecipientKeyResult` (Task 5)
- Produces:
  - top-level `fun splitAddresses(vararg commaJoined: String): List<String>`
  - `class ComposePgpController(pairingProvider: () -> PairingData?, bootstrapClient: PgpBootstrapClient, recipientKeyClient: RecipientKeyClient)`
  - `suspend fun composeState(): PgpComposeState`
  - `suspend fun keylessRecipients(addresses: List<String>): List<String>`
  - `companion object { fun resetSessionCache() }`

`ComposeActivity` is already 364 dense lines. Everything here is testable without a `Context`; the Activity renders and dispatches only.

**On caching:** the spec says fetch bootstrap once per app start. This fetches lazily on first compose and caches for the process lifetime, which is at most once per app start and skips the call entirely for users who never compose. **Only successes are cached** — caching a failure would disable encryption for the rest of the session over one flaky request.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.urlxl.mail

import com.urlxl.mail.pgp.PgpBootstrapClient
import com.urlxl.mail.pgp.PgpComposeState
import com.urlxl.mail.pgp.RecipientKeyClient
import com.urlxl.mail.push.PairingData
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Request
import okhttp3.Response
// …plus the FakeCallFactory/FakeCall/response block from PgpQrClientTest.kt:22-68
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.Before
import org.junit.Test

private fun testPairing(deviceId: String = "d", deviceSecret: String = "s") = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = deviceId,
    deviceSecret = deviceSecret,
    pairedAtEpochMs = 0L,
)

class ComposePgpControllerTest {

    /** The bootstrap cache is process-scoped, so it has to be cleared between tests. */
    @Before
    fun clearCache() = ComposePgpController.resetSessionCache()

    // ---- splitAddresses ----

    @Test
    fun splitAddresses_flattensTheThreeCommaJoinedFields() {
        assertEquals(
            listOf("a@example.com", "b@example.com", "c@example.com"),
            splitAddresses("a@example.com, b@example.com", "", "c@example.com"),
        )
    }

    /** The same address in To and CC is one recipient to check, and duplicate names in the
     *  confirmation dialog would read as two different people. */
    @Test
    fun splitAddresses_deduplicatesCaseInsensitively() {
        assertEquals(
            listOf("a@example.com"),
            splitAddresses("a@example.com", "A@Example.com", ""),
        )
    }

    @Test
    fun splitAddresses_dropsBlanksAndTrimsWhitespace() {
        assertEquals(listOf("a@example.com"), splitAddresses(" a@example.com , , ", "", ""))
    }

    // ---- composeState ----

    @Test
    fun composeState_mapsBootstrapThroughPgpComposeStateOf() = runBlocking {
        val controller = controllerWith(bootstrapBody = """{"hasIdentity":true,"protection":"server"}""")

        assertEquals(
            PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    /** Not paired is not "no identity": there is no account to ask about, so nothing is offered. */
    @Test
    fun composeState_withoutPairing_hidesEverything() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    @Test
    fun composeState_cachesASuccessForTheProcess() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, """{"hasIdentity":true,"protection":"server"}""", 200)
        }
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        controller.composeState()
        controller.composeState()

        assertEquals(1, calls)
    }

    /** A failure must not be cached: one flaky request would otherwise disable encryption for the
     *  rest of the session. */
    @Test
    fun composeState_doesNotCacheAFailure() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, "unavailable", 503)
        }
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        controller.composeState()
        controller.composeState()

        assertEquals(2, calls)
    }

    // ---- keylessRecipients ----

    @Test
    fun keylessRecipients_returnsTheAddressesWithNoKeyOnFile() = runBlocking {
        val body = """{"results":[
            {"address":"a@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"b@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val controller = controllerWith(recipientBody = body)

        assertEquals(
            listOf("b@example.com"),
            controller.keylessRecipients(listOf("a@example.com", "b@example.com")),
        )
    }

    /** A failed preflight yields no warning rather than a false one. The 409 is the real gate, so
     *  a failed lookup can never be the reason the fallback gets used. */
    @Test
    fun keylessRecipients_isEmptyOnFailure() = runBlocking {
        val controller = controllerWith(recipientStatus = 500, recipientBody = "boom")

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    @Test
    fun keylessRecipients_withoutPairing_isEmpty() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    private fun controllerWith(
        bootstrapBody: String = """{"hasIdentity":true,"protection":"server"}""",
        recipientBody: String = """{"results":[]}""",
        recipientStatus: Int = 200,
    ) = ComposePgpController(
        pairingProvider = { testPairing() },
        bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, bootstrapBody, 200) }),
        recipientKeyClient = RecipientKeyClient(
            callFactory = FakeCallFactory { request -> response(request, recipientBody, recipientStatus) },
        ),
    )
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --tests "*ComposePgpControllerTest*"`
Expected: FAIL — unresolved references `splitAddresses`, `ComposePgpController`.

- [ ] **Step 3: Implement**

```kotlin
package com.urlxl.mail

import android.content.Context
import com.urlxl.mail.pgp.PgpBootstrapClient
import com.urlxl.mail.pgp.PgpBootstrapResult
import com.urlxl.mail.pgp.PgpComposeState
import com.urlxl.mail.pgp.RecipientKeyClient
import com.urlxl.mail.pgp.RecipientKeyResult
import com.urlxl.mail.pgp.pgpComposeStateOf
import com.urlxl.mail.push.PairingData
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory

/**
 * Flattens the compose screen's three comma-joined recipient fields into one address list for the
 * preflight.
 *
 * Deduplicates case-insensitively: the same address in To and CC is one recipient to check, and
 * naming it twice in the confirmation dialog would read as two different people. The first spelling
 * wins, since that is the one the user typed and expects to see.
 */
fun splitAddresses(vararg commaJoined: String): List<String> {
    val seen = mutableSetOf<String>()
    return commaJoined
        .flatMap { it.split(',') }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filter { seen.add(it.lowercase()) }
}

/**
 * The compose screen's PGP decisions, kept out of [ComposeActivity] so they are testable without a
 * Context and so the Activity stays a view.
 *
 * Nothing here decides whether to *send*. The confirmation is driven by the relay's 409, not by the
 * preflight — see [keylessRecipients].
 */
class ComposePgpController(
    private val pairingProvider: () -> PairingData?,
    private val bootstrapClient: PgpBootstrapClient,
    private val recipientKeyClient: RecipientKeyClient,
) {

    /**
     * Which PGP controls this account gets. Cached for the process on success only — caching a
     * failure would disable encryption for the rest of the session over one flaky request.
     *
     * Returns the everything-hidden state when the device is not paired or bootstrap fails:
     * couldn't-check is not "no".
     */
    suspend fun composeState(): PgpComposeState {
        cachedState?.let { return it }
        val pairing = pairingProvider()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            return pgpComposeStateOf(hasIdentity = null, protection = null)
        }
        return when (val result = bootstrapClient.fetch(pairing.serverUrl, deviceId, deviceSecret)) {
            is PgpBootstrapResult.Success ->
                pgpComposeStateOf(result.hasIdentity, result.protection).also { cachedState = it }
            is PgpBootstrapResult.Failed -> pgpComposeStateOf(hasIdentity = null, protection = null)
        }
    }

    /**
     * The addresses with no usable key **in the user's contacts**, for an inline warning.
     *
     * A lower bound, never a promise: the send path also runs WKD and keyserver discovery, so an
     * address here may still be encrypted to successfully. A failure yields an empty list — no
     * warning rather than a false one — which is safe because the relay's 409 is the actual gate,
     * so a failed preflight can never be the reason the pickup fallback gets used.
     */
    suspend fun keylessRecipients(addresses: List<String>): List<String> {
        val pairing = pairingProvider()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return emptyList()
        return when (val result = recipientKeyClient.check(pairing.serverUrl, deviceId, deviceSecret, addresses)) {
            is RecipientKeyResult.Success -> result.keyless
            is RecipientKeyResult.Failed -> emptyList()
        }
    }

    companion object {
        /** Process-scoped, so a second compose in the same session costs no round trip. Not
         *  persisted: custody mode is fixed at key creation, but a re-pair to a different account
         *  restarts the process anyway (see AppRestart). */
        @Volatile
        private var cachedState: PgpComposeState? = null

        fun resetSessionCache() {
            cachedState = null
        }

        /** Wires the real, TLS-pinned clients. Mirrors [com.urlxl.mail.pgp.hasPgpIdentity]'s
         *  Context-based default. */
        fun from(context: Context): ComposePgpController = ComposePgpController(
            pairingProvider = { PushRuntime.graph(context).repository.pairingForAuthenticatedCall() },
            bootstrapClient = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(context)),
            recipientKeyClient = RecipientKeyClient(callFactory = pinnedPairingCallFactory(context)),
        )
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `./gradlew testDebugUnitTest --tests "*ComposePgpControllerTest*"`
Expected: PASS (all ten).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/ComposePgpController.kt app/src/test/java/com/urlxl/mail/ComposePgpControllerTest.kt
git commit -m "feat(pgp): add the compose PGP controller and recipient preflight"
```

---

### Task 8: Wire it into compose

**Files:**
- Modify: `app/src/main/res/layout/activity_compose.xml` (after the toolbar `LinearLayout` that ends at `:153`)
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/java/com/urlxl/mail/ComposeActivity.kt` — fields (`:38-57`), `onCreate` (`:63`), `applyToolbarChipsTheme` (`:184`), `sendEmail` (`:311-347`)

**Interfaces:**
- Consumes: everything from Tasks 1-7
- Produces: no new public API — this is the view layer

This task has no unit tests: it is Activity glue, and this repo does not instrument Activities (`PgpKeyActivity` has none either; its logic lives in tested pure functions, which is what Tasks 1-7 are). Its gate is `assembleDebug` plus the manual verification list.

- [ ] **Step 1: Add the strings**

In `strings.xml`, after the existing `compose_*` block:

```xml
    <string name="compose_pgp_encrypt">Encrypt</string>
    <string name="compose_pgp_sign">Sign</string>
    <string name="compose_pgp_webmail">Continue in webmail</string>
    <!-- Trap 2: the preflight reads contacts only, while the send path also runs WKD/keyserver
         discovery, so this must not promise that a link will be sent. -->
    <string name="compose_pgp_no_key_on_file">No PGP key on file for %1$s. They may still be found by key lookup when you send.</string>
    <!-- Spec § "Confirmation dialog copy": this wording carries the security property and is part
         of the contract. Do not soften it, and do not summarize the addresses. -->
    <string name="compose_pickup_dialog_title">Send an unencrypted link?</string>
    <string name="compose_pickup_dialog_body">We don\'t have a PGP key for %1$s. They\'ll get an email with a one-time link instead.\n\nTo make that work, this message\'s contents are stored on your KyPost server — unencrypted — for up to 7 days or until the link is opened. Everyone else on this message still gets it encrypted.</string>
    <string name="compose_pickup_dialog_confirm">Send link anyway</string>
    <string name="compose_handoff_dialog_title">Finish this in webmail</string>
    <string name="compose_handoff_dialog_body">This account\'s PGP key is held only by your browser, so neither this app nor your server can encrypt on your behalf. Your message has been saved as a draft — open webmail to finish sending it.</string>
    <string name="compose_handoff_dialog_confirm">Open webmail</string>
    <string name="compose_handoff_draft_failed">Couldn\'t save the draft, so webmail wouldn\'t have your message: %1$s</string>
    <string name="compose_handoff_no_webmail">Couldn\'t work out this server\'s web address — open your drafts in your browser.</string>
```

- [ ] **Step 2: Add the views**

In `activity_compose.xml`, immediately after the toolbar `LinearLayout` (closes at `:153`) and before the `composeMessageDivider` `View`:

```xml
    <!-- PGP row: hidden entirely unless GET /api/pgp/bootstrap said this account has an identity.
         Never shown optimistically — a toggle that 409s is worse than no toggle. -->
    <com.google.android.material.chip.ChipGroup
        android:id="@+id/composePgpChips"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:visibility="gone"
        android:layout_marginBottom="12dp"
        app:chipSpacingHorizontal="6dp">

        <com.google.android.material.chip.Chip
            android:id="@+id/composeEncryptChip"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:checkable="true"
            android:visibility="gone"
            android:text="@string/compose_pgp_encrypt" />

        <com.google.android.material.chip.Chip
            android:id="@+id/composeSignChip"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:checkable="true"
            android:visibility="gone"
            android:text="@string/compose_pgp_sign" />

        <com.google.android.material.chip.Chip
            android:id="@+id/composeWebmailChip"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:checkable="false"
            android:visibility="gone"
            android:text="@string/compose_pgp_webmail" />

    </com.google.android.material.chip.ChipGroup>

    <!-- "No key on file" notice. A warning callout, not an error: the send may still encrypt to
         these addresses via key discovery. -->
    <TextView
        android:id="@+id/composeKeylessWarning"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:visibility="gone"
        android:padding="12dp"
        android:layout_marginBottom="12dp" />
```

Both go inside the same parent as the toolbar row. Check the surrounding indentation and parent element in the file before pasting — the snippet above assumes the message card's `LinearLayout`.

- [ ] **Step 3: Hold the views, the controller, and the pending draft**

In `ComposeActivity`, alongside the existing `lateinit` fields (`:38-57`):

```kotlin
    private lateinit var pgpChips: ChipGroup
    private lateinit var encryptChip: Chip
    private lateinit var signChip: Chip
    private lateinit var webmailChip: Chip
    private lateinit var keylessWarning: android.widget.TextView
    private val pgpController by lazy { ComposePgpController.from(this) }

    /** The draft as it was actually sent, kept so the post-409 re-send reuses it byte-for-byte
     *  with only allowPickupFallback flipped. Re-exporting the editor HTML or re-encoding the
     *  attachments could produce a subtly different message. */
    private var sentDraft: MailDraft? = null
```

In `onCreate`, next to the other `findViewById` calls, then apply state:

```kotlin
        pgpChips = findViewById(R.id.composePgpChips)
        encryptChip = findViewById(R.id.composeEncryptChip)
        signChip = findViewById(R.id.composeSignChip)
        webmailChip = findViewById(R.id.composeWebmailChip)
        keylessWarning = findViewById(R.id.composeKeylessWarning)
        applyWarningCalloutTheme(this, keylessWarning)

        lifecycleScope.launch { applyPgpComposeState(pgpController.composeState()) }
```

Add `encryptChip`, `signChip` and `webmailChip` to the list in `applyToolbarChipsTheme` (`:185`) so they get `applyPillChipTheme`.

- [ ] **Step 4: Render the state and the preflight**

```kotlin
    /** Views only — the rule itself is [com.urlxl.mail.pgp.pgpComposeStateOf], unit-tested. */
    private fun applyPgpComposeState(state: PgpComposeState) {
        encryptChip.visibility = if (state.canEncrypt) View.VISIBLE else View.GONE
        signChip.visibility = if (state.canSign) View.VISIBLE else View.GONE
        webmailChip.visibility = if (state.handoffToWebmail) View.VISIBLE else View.GONE
        pgpChips.visibility =
            if (state.canEncrypt || state.canSign || state.handoffToWebmail) View.VISIBLE else View.GONE

        encryptChip.setOnCheckedChangeListener { _, checked ->
            if (checked) runPreflight() else hideKeylessWarning()
        }
        webmailChip.setOnClickListener { handOffToWebmail() }
    }

    /** Runs when Encrypt is switched on. Not debounced per keystroke: recipients are committed as
     *  chips by RecipientInputView rather than typed continuously, so this fires on a settled
     *  address list. */
    private fun runPreflight() {
        val addresses = splitAddresses(
            toInput.commaJoinedRecipients(),
            ccInput.commaJoinedRecipients(),
            bccInput.commaJoinedRecipients(),
        )
        lifecycleScope.launch {
            val keyless = pgpController.keylessRecipients(addresses)
            if (keyless.isEmpty()) {
                hideKeylessWarning()
            } else {
                keylessWarning.text =
                    getString(R.string.compose_pgp_no_key_on_file, keyless.joinToString(", "))
                keylessWarning.visibility = View.VISIBLE
            }
        }
    }

    private fun hideKeylessWarning() {
        keylessWarning.visibility = View.GONE
    }
```

**The Encrypt toggle is the only preflight trigger.** `RecipientInputView` exposes no recipient-changed callback (`recipientEmails()`/`commaJoinedRecipients()` are pull-only, and `addRecipient`/`commitTypedEmail` notify nobody), and adding one is not this plan's job. A recipient typed after the toggle went on is caught by the 409, which is the real gate anyway. Do **not** add a text watcher that fires per keystroke — it would hit `check` on every character.

- [ ] **Step 5: Send with the flags, and handle both 409s**

Replace the body of `sendEmail` (`:311`). The `MailDraft` is built once and stored; the retry reuses it:

```kotlin
    private fun sendEmail() {
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString().trim()
        val isBodyEmpty = bodyEditor.isEmptyFlow.value != false

        if (to.isBlank() || subject.isBlank() || isBodyEmpty) {
            Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show()
            return
        }

        sendMenuItem?.isEnabled = false

        bodyEditor.exportHtml { html ->
            val draft = MailDraft(
                to = to, cc = cc, bcc = bcc, subject = subject, body = html, mode = "html",
                attachments = attachments.toList(),
                sign = signChip.isChecked && signChip.visibility == View.VISIBLE,
                encrypt = encryptChip.isChecked && encryptChip.visibility == View.VISIBLE,
                // Never on for a first attempt. Only the post-409 re-send sets it, and only after
                // the user confirmed the dialog naming the addresses.
                allowPickupFallback = false,
            )
            sentDraft = draft
            dispatchSend(draft)
        }
    }

    /** Shared by the first attempt and the confirmed re-send, so the re-send cannot drift. */
    private fun dispatchSend(draft: MailDraft) {
        ioExecutor.execute {
            val outcome = MailRuntime.graph(this).repository.send(draft)
            runOnUiThread {
                when (outcome) {
                    is MailOutcome.Success -> {
                        val warning = outcome.value.warning
                        // The send already succeeded even when sentSaved is false or a pickup link
                        // failed — surface the warning as a notice, never as a failure, and never
                        // offer a retry that would duplicate the message.
                        Toast.makeText(this, warning.ifBlank { "Email sent successfully" }, Toast.LENGTH_SHORT).show()
                        finish()
                    }
                    is MailOutcome.PickupFallbackNeeded -> {
                        sendMenuItem?.isEnabled = true
                        confirmPickupFallback(outcome.keylessRecipients)
                    }
                    is MailOutcome.ClientSideNeeded -> {
                        sendMenuItem?.isEnabled = true
                        handOffToWebmail()
                    }
                    else -> {
                        sendMenuItem?.isEnabled = true
                        Toast.makeText(this, outcome.userFacingMessage(), Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /**
     * Nothing was delivered when this fires — the relay refuses before any SMTP — so the re-send
     * cannot duplicate the message.
     *
     * The copy is the spec's, verbatim, because it is what makes the opt-in meaningful. Cancel is
     * the negative button and the dialog stays cancelable, so dismissing keeps the composition.
     */
    private fun confirmPickupFallback(keylessRecipients: List<String>) {
        val draft = sentDraft ?: return
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_pickup_dialog_title)
            .setMessage(getString(R.string.compose_pickup_dialog_body, keylessRecipients.joinToString(", ")))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_pickup_dialog_confirm) { _, _ ->
                sendMenuItem?.isEnabled = false
                // The same draft, one flag flipped. Not rebuilt: no re-export of the editor HTML,
                // no re-encoded attachments, no second preflight.
                dispatchSend(draft.copy(allowPickupFallback = true))
            }
            .show()
    }
```

- [ ] **Step 6: Add the repository pass-through the handoff needs**

`MailRepository` exposes `send` (`MailRepository.kt:58`) but **not** `saveDraft`, and `relaySource` is private, so the handoff cannot reach it. Add next to `send`:

```kotlin
    /** Used by the client-custody webmail handoff: the composition is parked as a draft so the
     *  browser has something to open. Drafts carry no crypto flags — see [MailDraft]. */
    fun saveDraft(draft: MailDraft): MailOutcome<Unit> = relaySource.saveDraft(draft)
```

- [ ] **Step 7: Implement the webmail handoff**

```kotlin
    /**
     * Saves the composition as a draft and hands the Drafts URL to the **system**, so an installed
     * PWA or the user's browser opens it with the session it already has. Never an in-app WebView:
     * that shares no session and would put an account-password field inside this app.
     *
     * The draft save has to succeed first — opening a browser onto a draft that is not there loses
     * the user's message. The draft is saved without the PGP flags, which [MailDraft] handles by
     * mapping to the wire through a flagless function for /api/mail/draft.
     */
    private fun handOffToWebmail() {
        bodyEditor.exportHtml { html ->
            val draft = sentDraft ?: MailDraft(
                to = toInput.commaJoinedRecipients(),
                cc = ccInput.commaJoinedRecipients(),
                bcc = bccInput.commaJoinedRecipients(),
                subject = subjectField.text.toString().trim(),
                body = html,
                mode = "html",
                attachments = attachments.toList(),
            )
            ioExecutor.execute {
                val saved = MailRuntime.graph(this).repository.saveDraft(draft)
                val serverUrl = PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
                val url = serverUrl?.let { webmailDraftsUrl(it) }
                runOnUiThread {
                    when {
                        saved !is MailOutcome.Success -> Toast.makeText(
                            this,
                            getString(R.string.compose_handoff_draft_failed, saved.userFacingMessage().orEmpty()),
                            Toast.LENGTH_LONG,
                        ).show()
                        url == null -> Toast.makeText(this, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                        else -> showHandoffDialog(url)
                    }
                }
            }
        }
    }

    private fun showHandoffDialog(url: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_handoff_dialog_title)
            .setMessage(R.string.compose_handoff_dialog_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_handoff_dialog_confirm) { _, _ ->
                // Same guarded launch as EmailDetailActivity's "Open in webmail" button.
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                if (intent.resolveActivity(packageManager) != null) {
                    startActivity(intent)
                    finish()
                } else {
                    Toast.makeText(this, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                }
            }
            .show()
    }
```

New imports needed in `ComposeActivity.kt`: `android.content.Intent`, `android.view.View`, `com.urlxl.mail.pgp.PgpComposeState`, `com.urlxl.mail.pgp.webmailDraftsUrl`, `com.urlxl.mail.push.PushRuntime`. `Uri`, `AlertDialog`, `Chip`, `ChipGroup`, `lifecycleScope` and `launch` are already imported.

- [ ] **Step 8: Build and run the whole suite**

Run: `./gradlew assembleDebug testDebugUnitTest`
Expected: `BUILD SUCCESSFUL`, all tests pass.

- [ ] **Step 9: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/ComposeActivity.kt app/src/main/java/com/urlxl/mail/mail/MailRepository.kt app/src/main/res/
git commit -m "feat(pgp): offer encrypted send and the webmail handoff in compose"
```

---

### Task 9: Record the contract in AGENTS.md

**Files:**
- Modify: `app/src/main/AGENTS.md`

The file documents this app's non-obvious relay contracts; the two-409 discrimination and the never-`resolve` rule are exactly the kind of thing a future session would otherwise re-derive wrongly.

- [ ] **Step 1: Add the entry**

Add to the bullet list, near the existing PGP/relay entries:

```markdown
- Encrypted send: `MailDraft.sign`/`encrypt`/`allowPickupFallback` reach `/api/mail/send` through
  `toSendWireDto()`, deliberately *not* the shared `toWireDto()` — `/api/mail/draft` ignores them,
  so the draft path stays flagless. `/api/mail/send` has **two** 409s, told apart by which JSON
  field is present, never by status or error prose: `clientSideNeeded` (the account's key is
  client-custody; no re-send helps, hand off to webmail) and `keylessRecipients` (nothing was
  delivered; re-sending the *same* draft with `allowPickupFallback = true` is safe and cannot
  duplicate). Only those two 409s and the 200 are JSON — every other status returns plain text, so
  no decoder runs over it. The recipient preflight is `POST /api/pgp/recipients/check`, never
  `/resolve` (which 409s for every non-client-custody account); it reads contacts only, so
  `hasKey: false` is a lower bound and must never be worded as a promise. The pickup fallback
  stores the message's plaintext on the server for seven days, which is why its confirmation copy
  is fixed in `strings.xml` and is per-message — never a remembered preference.
```

- [ ] **Step 2: Commit**

```bash
git add app/src/main/AGENTS.md
git commit -m "docs: record the encrypted-send relay contract"
```

---

## Manual verification

Needs `kypost-server`'s `feat/mobile-encrypted-send` deployed and a paired device. None of the tasks above touch a real IMAP or SMTP server.

- [ ] Server-custody account with an identity → Encrypt and Sign chips appear; a recipient with a key in Contacts arrives encrypted.
- [ ] Server-custody, one keyless recipient → the dialog names that exact address and states the seven-day plaintext storage; Cancel keeps the composition intact and sends nothing; confirm delivers, and the keyless recipient receives a working link.
- [ ] The confirmed re-send does not duplicate: exactly one message arrives for the recipients who do have keys.
- [ ] Account with no PGP identity → no chips at all, plain send still works.
- [ ] Client-custody account → the webmail chip replaces the toggles; tapping it saves the draft and opens the system browser (or installed PWA) at Drafts with the composition intact; no in-app WebView appears.
- [ ] Client-custody with the draft save forced to fail (e.g. airplane mode) → the error shows and the compose screen stays open with the message intact.
- [ ] Airplane mode at compose open → no PGP chips appear (bootstrap failed, so nothing is offered), and a plain send still works once back online.
- [ ] A second compose in the same session shows the chips without a visible delay (bootstrap cached).
- [ ] Encrypt on, then off → the "no key on file" notice disappears.
- [ ] A partial-failure 200 (a pickup link that fails to deliver) shows the server's warning text and does not offer a retry.
