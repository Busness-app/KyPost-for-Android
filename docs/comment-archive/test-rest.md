# Comment archive - unit tests (non-pgp)

## app/src/test/java/android/util/Log.java
### `public final class Log {`
```
/**
 * A real {@code android.util.Log} for JVM unit tests, shadowing the stub in the mockable
 * android.jar.
 *
 * <p>This exists so {@code testOptions.unitTests.isReturnDefaultValues} can be <b>false</b>. With
 * it true, every unmocked {@code android.*} call in JVM-tested production code returned a default
 * <i>silently</i> — {@code android.util.Base64} returned null, {@code org.json} returned nothing —
 * so a suite could go green over a body that did nothing. {@code DeviceEnvelope}'s KDoc records
 * exactly that happening: its tests all passed vacuously, and replacing the whole function with
 * {@code = null} left the suite green.
 *
 * <p>The setting was true for one reason: logging. Production code with no {@code Context}
 * (AppLockManager, DeviceEnvelope, EnrollmentCeremony) has to be able to record a
 * security-relevant event without that making it untestable. Flipping the flag and shadowing this
 * one class gets both — every other stubbed API now throws loudly, which is the correct signal
 * given the project's own rule that JVM-tested production code must not call {@code android.*} for
 * anything but logging.
 *
 * <p>Writes to stderr rather than discarding, so a test that logs an error is visible in the
 * report instead of silent.
 */
```
Compressed to: `/** Real android.util.Log for JVM unit tests, shadowing the mockable android.jar stub. */`

## app/src/test/java/org/kysecurity/mail/ComposeAttachmentReadTest.kt
### `class ComposeAttachmentReadTest {`
```
/**
 * The outbound half of the attachment size bound.
 *
 * `ComposeActivity.addAttachment` used to call `readBytes()` and check the 25 MB cap against
 * `bytes.size` — i.e. after the whole document was already in the heap — while
 * `OpenableColumns.SIZE` was read and then never used. Picking a large file from a cloud provider
 * was an `OutOfMemoryError`, which `runCatching` does not catch, so it was a hard crash with an
 * unsent message in flight. [readAtMost] is what makes the refusal happen before the allocation.
 */
```
### `val payload = ByteArray(4096)`
```
        // Returning the prefix is the failure mode this exists to prevent: almost every file format
        // reads a truncated file without complaining, so the recipient gets a corrupt attachment and
        // the sender is never told.
```
### `val counting = CountingStream(totalBytes = 64 * 1024 * 1024)`
```
        // The bound has to hold on a stream whose length is not known up front — a provider that
        // under-reports or omits OpenableColumns.SIZE is exactly the case the declared-size
        // pre-check cannot catch.
```
Compressed to: `// A provider may under-report or omit OpenableColumns.SIZE, so length is unknown up front.`
### `private class CountingStream(private val totalBytes: Long) : InputStream() {`
```
    /** An endless-ish source that reports how much of itself was actually read. */
```

## app/src/test/java/org/kysecurity/mail/ComposeDraftCacheTest.kt
### `class ComposeDraftCacheTest {`
```
/**
 * Mirrors ContactEditDraftCacheTest's contract for the sibling cache: a draft survives Activity
 * destruction via save()/take(), take() hands ownership to the caller, clear() seals the cache
 * against a late write, and take() unseals for the next session. Plus the compose-specific rule
 * that an attachment alone — no text anywhere — is still worth keeping.
 */
```
### `@After`
```
    /** clear() deliberately seals, and this cache is a process-wide object shared by every test in
     *  the JVM. A bare clear() would leak that seal into the next test and silently no-op its
     *  save(); take() drops the draft *and* unseals, which is the pristine state. */
```
Compressed to: `/** The cache is process-wide: clear() seals it, and only take() unseals for the next test. */`
### `@Test`
```
    /** No recipients, no subject, no body — an attachment alone is still real work the user picked
     *  and would lose. "attachments included" is the spec's own phrase for this case. */
```

## app/src/test/java/org/kysecurity/mail/ComposePgpControllerTest.kt
### `@Test`
```
    // ---- splitAddresses ----

```
### `@Test`
```
    /** The same address in To and CC is one recipient to check, and duplicate names in the
     *  confirmation dialog would read as two different people. */
```
### `@Test`
```
    // ---- composeState ----

```
### `@Test`
```
    /** Not paired is not "no identity": there is no account to ask about, so nothing is offered. */
```
### `@Test`
```
    /** The cache is `companion object`-scoped (process-wide), not per-instance — a controller
     *  created fresh for a second compose screen still must not re-hit the network. Calling
     *  composeState() twice on the *same* instance would pass even against a per-instance cache,
     *  so this exercises two separate instances sharing one call factory to actually pin the
     *  process-wide scoping the design (and [PushRepository.purgeAccountScopedData]'s explicit
     *  invalidation of it on unpair) depends on. */
```
### `@Test`
```
    /** A failure must not be cached: one flaky request would otherwise disable encryption for the
     *  rest of the session. */
```
### `@Test`
```
    /**
     * Custody mode is fixed at key creation and safe to cache; **enrollment is not**.
     *
     * The user can enrol part-way through a session, and the OS can invalidate the Keystore key
     * underneath us. Caching the composed state would freeze whichever answer came first — leaving
     * a freshly enrolled device stuck on the webmail handoff for the rest of the process, or
     * offering a Send whose key no longer opens.
     */
```
### `@Test`
```
    /** The address every delivery's From must carry, read off the cached bootstrap. */
```
### `@Test`
```
    // ---- keylessRecipients ----

```
### `@Test`
```
    /** A failed preflight yields no warning rather than a false one. The 409 is the real gate, so
     *  a failed lookup can never be the reason the fallback gets used. */
```
Compressed to: `/** The server's 409 is the real gate, so a failed lookup must never force the fallback. */`

## app/src/test/java/org/kysecurity/mail/EmailAdapterUpdateTest.kt
### `class EmailAdapterUpdateTest {`
```
/** Covers [dispatchEmailListUpdate] — regression test for the swipe-to-delete background staying
 *  painted under the inbox until the app is force-stopped.
 *
 *  ItemTouchHelper does not call `onSwiped` inline; it posts a runnable, and that runnable gives up
 *  for good when the swiped ViewHolder's adapter position reads NO_POSITION (ItemTouchHelper.java,
 *  `postDispatchSwipe`). `notifyDataSetChanged()` marks every attached holder invalid, so positions
 *  read NO_POSITION until the next layout pass — and a second swipe landing in that window is
 *  dropped. Its recover animation then stays in `mRecoverAnimations` forever, because the pruning
 *  loop skips animations still flagged pending-cleanup, so `onChildDraw` keeps drawing the red
 *  delete background every frame and the message is never deleted from the server.
 *
 *  So the inbox list must report what actually changed instead of invalidating the whole list. */
```
Compressed to: `/** Granular updates only: notifyDataSetChanged() breaks in-flight ItemTouchHelper swipes. */`
### `@Test`
```
    /** The swipe path deletes one row at a time, so back-to-back swipes must each stay granular. */
```
### `@Test`
```
    /** A background poll that changes nothing must not disturb an in-flight swipe. */
```

## app/src/test/java/org/kysecurity/mail/EmailDetailActivityTest.kt
### `class EmailDetailActivityTest {`
```
/**
 * Covers [buildEmailBodyHtml] and [stripImportant] — the pure pieces pulled out of
 * [EmailDetailActivity]'s body-loading callback. Regression tests for two real bugs:
 *
 * 1. Emails that hardcode their own inline `color`/`background-color` (virtually all of them) were
 *    only partly overridden by the app's dark theme, since a plain `body { color; background-color }`
 *    rule loses to any more specific/inline declaration an email brings for its own descendants —
 *    producing black-on-dark-background for emails that only set text color, and black-on-white
 *    (ignoring the app's theme entirely) for emails that set both.
 * 2. After fixing (1) with a wildcard `!important` override, emails that mark their *own*
 *    background/text color `!important` too (common in templates defending against Gmail/Outlook/
 *    Apple Mail's automatic dark-mode recoloring) still won — an inline `style="...!important"`
 *    outranks any external stylesheet rule regardless of specificity once both sides are
 *    `!important`, producing white-on-white for emails with an `!important`-forced white background.
 */
```
### `assertTrue(html.contains(emailWithOwnTextColorOnly))`
```
        // The email's own markup must survive untouched — overriding happens via CSS, not by
        // stripping/rewriting the email's HTML.
```
### `assertTrue(html.contains("color: ${lightPalette.inkStrong};"))`
```
        // The plain (non-important) body rule from before this fix must still be present.
```
### `val emailPortion = html.substringAfter("<table")`
```
        // The email's own !important must be gone (the property values it guarded, #ffffff/#000000,
        // are left in place — harmless once stripped of their importance, since body * still forces
        // transparent/inkStrong over them; it's specifically the token that let them out-rank our
        // override that must go). Our own override rules' !important (in the <style> block, before
        // <table>) is untouched and expected.
```
### `@Test`
```
    // ---- stripImportantFromCss: token removal within one declaration block ----

```
### `for (hex in listOf("110000", "ffffff", "FFFFFF", "7FFFFF")) {`
```
        // CSS_ESCAPE accepts six hex digits (up to 0xFFFFFF) while Character.toChars THROWS above
        // 0x10FFFF. The sender picks this value, and it used to reach EmailDetailActivity's
        // ioExecutor as an uncaught IllegalArgumentException — a process kill that repeated on
        // every reopen, because the message stays in the mailbox.
```
Compressed to: `// CSS_ESCAPE accepts six hex digits (0xFFFFFF); Character.toChars throws above 0x10FFFF.`
### `@Test`
```
    // ---- stripImportant: which parts of the document the removal reaches ----

```
### `@Test`
```
    /**
     * The old version was a text sweep over the whole body, so it rewrote prose. `!important` in
     * visible text is not a CSS declaration and removing it changes what the message says.
     */
```
### `@Test`
```
    /**
     * Parsing means the token patterns only ever see one attribute or one `<style>` block, so the
     * inputs that made the whole-body regex quadratic — an unclosed comment, a body of nothing but
     * whitespace — are no longer reachable, and the 512KB "skip it entirely" cap is gone with them.
     * Measured before: ~23s at 128KB, ~4 minutes at 512KB, from a body containing no `!` at all.
     */
```
### `@Test`
```
    /** No size cap any more: a large body is still cleaned, because the parse bounds the work
     *  instead of the length check doing it. */
```
### `@Test`
```
    // ---- attachment name and type sanitising ----

```
### `@Test`
```
    /**
     * The extension is derived from the type this app decided to declare, never from the sender's
     * filename. Previously the name's own suffix survived sanitisation intact, so
     * `invoice.pdf\u0000.apk` came out as `invoice.pdf.apk`: the MIME type handed to MediaStore
     * was already downgraded to octet-stream, but the name a user sees in a file picker still read
     * as an installer.
     */
```
### `assertEquals("payload", safeFileName("payload.apk", "application/vnd.android.package-archive"))`
```
        // A type this app will not declare gets no extension at all rather than the sender's.
```
### `private val nonRetryableOutcomes = listOf(`
```
    // isDarkPalette() itself (the bg-luminance → dark/light classification) calls
    // android.graphics.Color.parseColor, which isn't available in a plain JVM unit test (no
    // Robolectric in this module — see every other test file's Android-framework-free style) —
    // covered instead by buildEmailBodyHtml's own isDark parameter above, and by manual/instrumented
    // verification that a dark theme's palette.bg does trigger the override branch in the real app.

    // ---- showsRetryButton: which ReadOutcome offers a Retry tap ----
```
Compressed to: `// isDarkPalette() needs android.graphics.Color, so it is not covered here; isDark is passed in.`
### `private val nonRetryableOutcomes = listOf(`
```
    /** Every non-FetchFailed row of the exit table, once each. The two easiest to confuse with a
     *  transport failure are the actual target: [ReadOutcome.NoEncryptedContent] is terminal (the
     *  server answered "no payload"; retrying cannot change that) and [ReadOutcome.DecryptFailed]
     *  is a local decrypt failure, not a fetch failure — neither should offer Retry. */
```
### `@Test`
```
    /** [ReadOutcome.NoEncryptedContent] specifically: the server answered, so a Retry button here
     *  would invite the user to tap it forever. Deliberate-break check inline, not just a shared
     *  loop assertion, since this is the one row the brief calls out by name as never-Retry. */
```
### `private val decryptedBody = DecryptedBody(html = "<p>hi</p>", plain = null, protectedSubject = null)`
```
    // ---- displaySignatureVerdict: the verdict actually safe to display ----

```
### `@Test`
```
    /**
     * The security case this function exists for: PgpPayloadResult.resolvedSender's own KDoc says
     * it is empty "e.g. [for] a multi-mailbox From" — exactly the attacker-separable shape ("Bob
     * Smith (Eve <eve@evil.example>) <bob@example.com>" and its relatives) the resolved-vs-raw
     * sender display rule exists for. A non-NONE signature with no resolved mailbox to pin it to
     * must not reach the screen, where it would read as being about whatever raw sender text is
     * still displayed.
     */
```
### `@Test`
```
    // ---- mayReplyOrForward: which PgpMessageState blocks Reply/Reply-All/Forward ----

    /** The one state Task 11 exists for: no safe destination for a quoted decrypted body, so this
     *  must be false even once the message has been decrypted on screen — see
     *  EmailDetailActivity.applyReplyForwardAvailability's KDoc for why that has to hold
     *  unconditionally rather than just before decrypt succeeds. */
```
### `@Test`
```
    /** Every other state must stay true, so a change that widens the block (e.g. mistakenly
     *  gating on DECRYPT_FAILED too) fails a test rather than shipping silently disabled buttons
     *  on messages with a perfectly good server-side body. Enumerated via [PgpMessageState.entries]
     *  rather than hand-listed, so a future state added to the enum is covered automatically
     *  instead of silently passing unchecked. */
```
### `@Test`
```
    // ---- initialReplyForwardState: the fail-closed default before renderBody's fetch answers ----

    /** The case this function exists for: `renderBody`'s background fetch may take a network
     *  round trip, or never complete at all if it throws, so an encrypted message must default to
     *  blocked — not to allowed-until-proven-otherwise — or Reply is live for that whole window on
     *  exactly the messages this task exists to protect. */
```
### `@Test`
```
    /** An unencrypted message was never going to become CLIENT_PROTECTED, so it isn't held
     *  hostage to the same wait. */
```

## app/src/test/java/org/kysecurity/mail/InMemoryPlaintextTest.kt
### `class InMemoryPlaintextTest {`
```
/**
 * The security wipe and the account purge both have to destroy message plaintext that never
 * reaches disk. Neither can be unit-tested directly (one is Android-only, the other needs Room),
 * so the shared clear is a plain function and this is where it is pinned.
 */
```

## app/src/test/java/org/kysecurity/mail/SourceRulesTest.kt
### `class SourceRulesTest {`
```
/**
 * Two project rules that were previously stated in KDoc and enforced by nothing, asserted against
 * the source tree itself.
 *
 * Both had already been violated by the time they were written down — three files carried the very
 * `ByteArray`-in-a-`data class` shape that three other files each spend a paragraph forbidding —
 * which is the argument for this file existing. A rule a human has to remember is not a rule.
 *
 * Reads the tree as text rather than through reflection or a linter dependency: it needs no new
 * artifact in `gradle/verification-metadata.xml`, and it is unaffected by
 * `isReturnDefaultValues = true` because it touches no `android.*` API.
 */
```
### `@Test`
```
    /**
     * `data class` + a key-material property means Kotlin generates identity `equals`/`hashCode`
     * while the type advertises structural equality — a silent trap on exactly the types that hold
     * key material, ciphertext and plaintext.
     *
     * A class that writes both overrides itself has made the decision deliberately and is allowed;
     * see `PgpDecryptor.DecryptResult.Ok`.
     *
     * The type list is not just `ByteArray`. It was, and that was the wrong half of the problem:
     * `ByteArray`'s generated `toString()` prints `[B@1f2e3d`, which leaks nothing, while
     * `SecretKeySpec` and `CharArray` sit in the same trap and `CredentialKeys` was carrying two of
     * the former the whole time this rule was green.
     */
```
### `@Test`
```
    /**
     * A `data class` whose generated `toString()` would print a secret or a plaintext message body
     * must override it.
     *
     * **This is the half the `ByteArray` rule above never covered, and it is the half that leaks.**
     * `ByteArray.toString()` is an identity hash. `String.toString()` is the string — so
     * `DecryptedBody`, whose whole purpose is to hold a decrypted message, printed the entire mail
     * into any `Log.e(TAG, "...$outcome")` or crash-reporter frame that ever touched it. Nothing in
     * the tree does that today; the point is that adding the line is a one-token change and nothing
     * would have failed.
     *
     * Matched on **property name**, deliberately, because the type cannot answer this: `body:
     * String` and `serverUrl: String` are the same type and only one of them is mail. Crude, and
     * the same kind of crude as the reader below — a new field called `plaintext` that does not need
     * redacting is a two-second suppression, while a new field called `plaintext` that does is
     * exactly what this catches.
     */
```
### `@Test`
```
    /**
     * `isReturnDefaultValues = true` makes every stubbed `android.*` call return a default instead
     * of working. Most stubs are harmless in a JVM test — nothing exercises a `TextView`. These two
     * are not: `android.util.Base64` returns null and `org.json` returns nothing, *silently*, so a
     * suite over code that uses them passes without testing anything. `DeviceEnvelope`'s KDoc
     * records a suite that stayed green against a `= null` body for exactly this reason.
     *
     * Scoped to production files that have a same-named JVM test, which is the only place the
     * failure mode is reachable — and is a check with no reachability guesswork in it. Use
     * `java.util.Base64` and `kotlinx.serialization` instead; code that genuinely needs the
     * framework belongs in `src/androidTest`.
     */
```
### `private class Source(val path: String, val relativePath: String, private val file: File) {`
```
    // --- source tree -------------------------------------------------------------------------

```
### `private class DataClass(val name: String, val parameters: String, private val body: String) {`
```
    // --- the crude Kotlin reader these two rules need ----------------------------------------

```
### `fun parameterNames(): List<String> {`
```
        /**
         * The declared property names, at the top level of the parameter list only.
         *
         * Depth-tracked so a default value that is itself a call with named arguments — or a
         * generic type argument — cannot contribute a name. `val` prefix required, so a plain
         * constructor parameter that is not a property is not matched either.
         */
```
### `private fun dataClassesIn(source: String): List<DataClass> =`
```
    /**
     * Every `data class` header in [source], with its constructor parameter list and the text that
     * follows it.
     *
     * Balanced-paren scanning rather than a single regex: a parameter's own default value can
     * contain parentheses, and `[^)]*` stops at the first one. Deliberately not a Kotlin parser —
     * the rules above are about a declaration's shape, and a parser is a dependency this check does
     * not need.
     */
```
### `const val BODY_SCAN_CHARS = 1200`
```
        /** How far past a class header to look for hand-written equality overrides. Generous: the
         *  cost of over-reading is a false pass on one class, and the cost of under-reading is a
         *  build that fails on a class that did the right thing. */
```
Compressed to: `/** How far past a class header to look for equality overrides; generous on purpose. */`
### `val PARAM_IS_KEY_MATERIAL =`
```
        /**
         * Types whose generated `equals`/`hashCode` are identity-based while the declaration
         * advertises structure. `SecretKeySpec` is here because `CredentialKeys` held two.
         */
```
Compressed to: `/** Types whose generated `equals`/`hashCode` are identity-based, not structural. */`
### `val SENSITIVE_PROPERTY_NAMES = setOf(`
```
        /**
         * Property names that mean "this holds a secret or a plaintext message body".
         *
         * `publicKey` is deliberately ABSENT: it is public by construction, it is rendered in the
         * UI, and including it would have put a redaction requirement on eight DTOs that lose
         * nothing by printing.
         */
```
Compressed to: `/** Names meaning "holds a secret or plaintext"; `publicKey` is deliberately absent. */`
### `"plaintext", "body", "html", "plain", "preview", "protectedSubject", "encryptedPayload",`
```
            // Decrypted or cached message content.
```
### `"secret", "deviceSecret", "pairingToken", "passphrase",`
```
            // Credentials and key material.
```
### `val IMPORT = Regex("""^import\s+([\w.]+)""", RegexOption.MULTILINE)`
```
        // `pin` is deliberately ABSENT, and it is the one name that looks like it belongs. The only
        // `pin` property in the tree is `TlsPinState.Pinned.pin` — an SPKI hash of a *public*
        // certificate, which is useful in a log and secret from nobody. The app-lock PIN is never a
        // property: it lives in a `CharArray` that is passed, used and zeroed, so the key-material
        // rule above is what covers it.
```
Compressed to: `// `pin` is absent on purpose: the only `pin` property is an SPKI hash of a public cert.`

## app/src/test/java/org/kysecurity/mail/contacts/ContactAdapterTest.kt
### `class ContactAdapterTest {`
```
/** Covers [contactHasLinkedPgpKey] — regression test for the self-contact's "PGP" badge showing
 *  "not linked" even when the account has a real PGP identity on the server. The self-contact's own
 *  `pgpKey` field (see `contacts.go`/`pgp_qr_handlers.go` on the server) is a normal, independently
 *  editable contact field with no connection to the account's actual PGP identity, so the badge must
 *  also honor the account-level [hasPgpIdentity] signal for that one contact specifically. */
```
Compressed to: `/** The self-contact's own `pgpKey` field is unrelated to the account's real PGP identity. */`

## app/src/test/java/org/kysecurity/mail/contacts/ContactDetailActivityTest.kt
### `class ContactDetailActivityTest {`
```
/** Covers the pure formatting helpers [ContactDetailActivity] uses to render a contact read-only:
 *  [contactSubtitle], [formatAddress], [urlWithScheme]. Pulled out of the Activity for the same
 *  reason as [mergedContactDto] in `ContactEditActivity` — unit-testable without a Context-backed
 *  Activity. */
```
### `@Test`
```
    // ---- contactSubtitle ----

```
### `@Test`
```
    // ---- formatAddress ----

```
### `@Test`
```
    // ---- urlWithScheme ----

```

## app/src/test/java/org/kysecurity/mail/contacts/ContactEditActivityTest.kt
### `class ContactEditActivityTest {`
```
/**
 * Covers [mergedContactDto] — the pure piece pulled out of [ContactEditActivity.save] (mirrors
 * [ContactSyncRepositoryTest]'s extraction approach for the same reason: unit-testable without a
 * Context-backed Room/Activity). Regression test for a real data-loss bug: `save()` used to build a
 * brand-new [ContactDto] from only the fields this single-screen editor exposes, so saving any edit
 * (even just fixing a phone number) silently wiped every other field — locally immediately, and on
 * the server too, since both the local upsert and the server's PUT/push handlers fully replace the
 * stored contact rather than merging. [mergedContactDto] must `.copy()` off the loaded contact
 * instead.
 */
```

## app/src/test/java/org/kysecurity/mail/contacts/ContactEditDraftCacheTest.kt
### `class ContactEditDraftCacheTest {`
```
/**
 * Mirrors ComposeDraftCacheTest's contract: a draft survives Activity destruction, a take() hands
 * ownership to the caller, and a clear() seals the cache against a late write from the session
 * that was just wiped. Plus the contact-specific rule that a draft only ever goes back to the
 * contact it came from.
 */
```
### `@After`
```
    /** clear() deliberately seals, and this cache is a process-wide object shared by every test in
     *  the JVM. A bare clear() would leak that seal into the next test and silently no-op its
     *  save(); take() drops the draft *and* unseals, which is the pristine state. */
```
Compressed to: `/** The cache is process-wide: clear() seals it, and only take() unseals for the next test. */`
### `@Test`
```
    /**
     * The app lock finishes the editor and the unlock returns the user to the inbox, so contact A's
     * draft can outlive A's screen. It must not then be handed to contact B, whose save would
     * overwrite B with A's fields under B's uid.
     */
```
### `@Test`
```
    /** A mismatch drops the draft rather than leaving it to find a later victim. */
```

## app/src/test/java/org/kysecurity/mail/contacts/ContactMappersTest.kt
### `@Test`
```
    // ---- pgpKey fingerprint verification / rotation detection ----

```
### `val previous = ContactEntity(uid = "uid-8", rev = 1, fn = "Alice", pgpKeyFingerprint = TEST_KEY_FINGERPRINT)`
```
        // A device-side edit carries the key over untouched, so the fingerprint is unchanged and
        // the rotation check cannot fire — but the key no longer vouches for the address it is
        // displayed beside. Any app holding WRITE_CONTACTS can drive this.
```
Compressed to: `// A device-side edit keeps the key, so only the address the key vouches for changed.`
### `val previous = ContactEntity(uid = "uid-9", rev = 1, fn = "Bob")`
```
        // Nothing is vouching for anything, so there is no alarm to raise. Flagging here would
        // put a reverification badge on every ordinary contact edit.
```
### `val previous = ContactEntity(uid = "uid-10", rev = 1, fn = "Carol", pgpKeyFingerprint = "AAAA BBBB")`
```
        // The QR ceremony attests to the KEY: the user compared this fingerprint against the other
        // person's device, so a rotation it confirms must clear rather than raise — otherwise the
        // app's only TOFU alarm fires on the one path where reverification is provably unnecessary,
        // and users learn to dismiss it.
```
### `val previous = ContactEntity(uid = "uid-11", rev = 1, fn = "Carol", pgpKeyFingerprint = TEST_KEY_FINGERPRINT)`
```
        // ...but it attests to nothing about WHICH ADDRESSES that key is bound to. The QR save path
        // builds its DTO from the current Room row, while the confirmation screen shows the
        // addresses from the scanned card — so a WRITE_CONTACTS app could inject an address, and the
        // user's own recommended remediation (scan the key again) would clear the alarm that
        // injection raised. A rebind is a different claim from a rotation and outlives the ceremony.
```
Compressed to: `// A rebind is a different claim from a rotation, so it outlives the QR ceremony.`
### `@Test`
```
    /**
     * The attack the split exists for, replaying the exact production call sequence.
     *
     * A WRITE_CONTACTS app rewrites Alice's phone number. The next sync raises the alarm. The user
     * does the obvious thing for a contact-trust warning — meets Alice, scans her QR, compares the
     * fingerprint — and `PgpKeyActivity` saves with `identityChanged = false, verifiedInPerson =
     * true`. With one shared column that cleared the alarm, leaving the attacker's phone number
     * beside a just-verified key with no warning anywhere, on the device and on the relay.
     *
     * Note the previous regression test passed `identityChanged = true` alongside
     * `verifiedInPerson = true` — a combination no production call site ever produces — which is why
     * the suite reported this property as covered when it was not.
     */
```
### `assertTrue(entity.pgpKeyNeedsReverification)`
```
        // PgpFingerprint.compute returns null for the shapes it refuses to vouch for — an appended
        // second key ring, a subkey bound by a foreign signature — and its KDoc says callers must
        // treat null as "reject this key". Reading it as "no information" let an attacker silence
        // the only key alarm that does not depend on the relay's own verdict, simply by choosing an
        // encoding the local parser rejects.
```
Compressed to: `// PgpFingerprint.compute returns null for keys it refuses to vouch for; null means reject.`
### `assertTrue(entity.pgpKeyNeedsReverification)`
```
        // stillNeedsReverification requires newFingerprint == previousFingerprint, which a null
        // fingerprint can never satisfy — so an outstanding alarm was being cleared rather than
        // carried forward.
```

## app/src/test/java/org/kysecurity/mail/contacts/ContactSyncRepositoryTest.kt
### `class ContactSyncRepositoryTest {`
```
/**
 * Covers [contactDedupeOutcomeOf] and [resolveDedupeOutcome] — the pure, dependency-free pieces
 * pulled out of [ContactSyncRepository.dedupe] so they're unit-testable without a real
 * Context-backed `AppDatabase`/`ContactCursorStore` (mirrors
 * [org.kysecurity.mail.mail.reconcileFetchResult]'s extraction from `MailRepository` for the same
 * reason — see `MailRepositoryTest.kt`). `ContactSyncRepository` itself still has no direct unit
 * tests; that gap is pre-existing repo-wide infra (no Robolectric/mocking library) and unaffected
 * by this extraction.
 */
```
### `@Test`
```
    // --- contactDedupeOutcomeOf: pure ContactDedupeResult -> ContactDedupeOutcome mapping ---

```
### `@Test`
```
    // --- resolveDedupeOutcome: the pairing short-circuit that dedupe() decides before calling the client ---

```

## app/src/test/java/org/kysecurity/mail/contacts/GroupsSyncClientTest.kt
### `private class GroupsFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {`
```
/** Fakes OkHttp's [Call.Factory], mirroring [ContactSyncClientTest]'s hand-rolled-fake style (no
 *  mocking framework, no MockWebServer dependency in this repo). Named distinctly from
 *  [ContactSyncClientTest]'s identically-shaped private fakes since both files share the
 *  `org.kysecurity.mail.contacts` package -- top-level `private` classes are still package-namespaced
 *  at the JVM level, so same-named fakes across files in one package would collide. */
```
Compressed to: `/** Named distinctly from [ContactSyncClientTest]'s fakes: same package, so JVM names collide. */`

## app/src/test/java/org/kysecurity/mail/contacts/RecipientMatchingTest.kt
### `val comma = ContactEntity(`
```
        // ContactsContract has no per-account write ACL, so any app holding WRITE_CONTACTS can set
        // this value. Chips are joined with "," on the wire and the relay additionally rewrites ";"
        // to "," before parsing the address list, so a separator inside one contact's address turns
        // a single picked chip into two SMTP recipients — while the chip still shows only the
        // contact's display name.
```
Compressed to: `// Any app with WRITE_CONTACTS can set this; a separator splits one chip into two.`

## app/src/test/java/org/kysecurity/mail/contacts/Run4ContactBoundaryProbeTest.kt
### `class Run4ContactBoundaryProbeTest {`
```
/**
 * SCRATCH / AUDIT PROBE — run-4 security audit, safe to delete.
 *
 * Reproduces the exact expressions used by
 * `DeviceContactRepository.pullDeviceChangesForOwnAccount` (the `changed` predicate at :252-259
 * and the `identityChanged` predicate at :283) over the real `DeviceContactFieldMerge` /
 * `DeviceContactMatcher` / `ContactMappers` production functions, so the boundary claims are
 * demonstrated rather than argued.
 */
```
Compressed to: `/** SCRATCH / AUDIT PROBE — run-4 security audit, safe to delete. */`
### `@Test`
```
    // ---------------------------------------------------------------------------------------
    // A. identityChanged covers only `emails` and `fn`. Every other identity-bearing field can be
    //    rewritten by a WRITE_CONTACTS app, uploaded to the relay, and leave the trust badge green.
    // ---------------------------------------------------------------------------------------

```
### `@Test`
```
    // ---------------------------------------------------------------------------------------
    // B. The QR ceremony clears a reverification alarm that was raised about ADDRESSES, having
    //    verified only the KEY. PgpKeyActivity.saveKeyToContact:333-340 builds the DTO from the
    //    (already tampered) Room row and passes verifiedInPerson = true.
    // ---------------------------------------------------------------------------------------

```
### `@Test`
```
    // ---------------------------------------------------------------------------------------
    // C. DeviceContactMatcher.Index indexes empty normalized values, creating wildcard buckets.
    // ---------------------------------------------------------------------------------------

```
### `val existing = listOf(`
```
        // Regression: a single stored contact carrying a placeholder phone used to poison the whole
        // index, because normalizePhone strips every non-digit and "n/a" collapses to "". Every
        // later candidate whose phone had no digits then matched THAT contact and was silently
        // skipped by importNewDeviceContacts — so unrelated contacts were never imported.
```
Compressed to: `// normalizePhone strips every non-digit, so a placeholder like "n/a" collapses to "".`
### `@Test`
```
    // ---------------------------------------------------------------------------------------
    // D. Control: a device-side merge can never clear a stored key, so the ONLY way a
    //    WRITE_CONTACTS app can destroy a pinned key is the DELETE branch — which drops the Room
    //    row (key, fingerprint and alarm together) before any server round trip.
    // ---------------------------------------------------------------------------------------

```

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactFieldCodingTest.kt
### `@Test`
```
    // --- imCustomProtocolLabel ---

```
### `@Test`
```
    // --- imServiceFromCustomProtocolLabel (read-path inverse) ---

```
### `@Test`
```
    // --- relationType / relationCustomLabel ---

```
### `@Test`
```
    // --- eventType / eventCustomLabel ---

```
### `@Test`
```
    // --- relationLabelFromType (read-path inverse) ---

```
### `@Test`
```
    // --- eventLabelFromType (read-path inverse) ---

```

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactFieldMergeTest.kt
### `@Test`
```
    // --- mergeImList ---

```
### `@Test`
```
    // --- mergeWebsiteList ---

```
### `@Test`
```
    // --- mergeRelationList ---

```
### `@Test`
```
    // --- mergeEventList ---

```

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactMappersTest.kt
### `class DeviceContactMappersTest {`
```
/**
 * [DeviceContactMappers.ContactEntity.toDto] is the merge base for both directions of device
 * sync ([DeviceContactRepository.pullDeviceChangesForOwnAccount]'s `roomDto.copy(...)` and
 * [DeviceContactRepository.pushRoomChangesToDevice]'s `entity.toDto()`). It used to be its own
 * partial re-implementation that silently dropped every Task-2-added field — this test guards
 * against that regression by asserting the fields this task's device provider wiring never
 * touches (`pgpKey`/`pronouns`/`customFields`/`groupIDs`/`photoRef`) still survive the
 * `ContactEntity -> ContactDto` conversion used on every device sync pass, per
 * `Client_Contact_Update.md`'s Part 5 checklist item.
 */
```

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactMatcherTest.kt
### `@Test`
```
    /** Matching on any address in the list, not just the first, is the whole point — a contact with
     *  three emails must be found by its third. */
```
### `@Test`
```
    /**
     * The index must answer exactly as the old per-candidate rescan did: the first contact in list
     * order that matches on *either* field, never whichever field happens to be checked first.
     */
```

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceContactPurgeOutcomeTest.kt
### `class DeviceContactPurgeOutcomeTest {`
```
/**
 * The rule that decides whether a security wipe may claim it destroyed the user's contacts.
 *
 * `DeviceContactPurge.deleteSyncedRows` used to map every `SecurityException` to `0` — "no rows
 * deleted, and that is fine" — on the reasoning that no WRITE_CONTACTS meant this app had never
 * published a row. Runtime permissions are revocable, by the user and (since Android 11) by the OS
 * auto-resetting them for unused apps, so that reasoning is wrong in exactly the case that matters:
 * sync was enabled, rows were published, the permission went away afterwards.
 *
 * `SecurityWipe.deleteSyncedDeviceContactRows` treats `0` as success and only a negative count as a
 * failure, so the wipe reported `Complete` while the user's whole address book was still in
 * ContactsContract — outside the app sandbox, readable by every app holding READ_CONTACTS and
 * visible in the phone's own Contacts app.
 */
```
### `assertEquals(0, deniedPermissionRowOutcome(accountExists = false))`
```
        // No account means no rows can exist: CP2 hard-deletes an account's raw contacts when the
        // account goes, and nothing else writes under this account type. Reporting a failure here
        // would make every wipe on a device that never enabled sync — the default — read as
        // Incomplete, which is the over-correction the original comment was guarding against.
```
Compressed to: `// No account means no rows: CP2 hard-deletes an account's raw contacts with it.`

## app/src/test/java/org/kysecurity/mail/contacts/device/DeviceGroupLinkerTest.kt
### `class DeviceGroupLinkerTest {`
```
/** Covers [findExistingGroupRowId], the pure find-by-title decision [DeviceGroupLinker] uses to
 *  avoid duplicating an on-device group the user already has — the class itself needs a real
 *  `ContentResolver`/`AppDatabase` so isn't directly unit-testable in this repo's no-Robolectric
 *  JVM test setup (same gap `ContactSyncRepositoryTest.kt` documents for `ContactSyncRepository`).
 *  Also covers [groupRenameTargets], the pure join [DeviceContactRepository] uses to detect which
 *  *already-linked* groups need a rename pass on every sync cycle (not just newly-created
 *  contacts) — the fix for the plan's Part 2 point 4 gap. */
```
### `val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 42L))`
```
        // groupRenameTargets always resolves the current fresh name for every existing link --
        // whether that name actually differs from the on-device title is decided later by
        // DeviceGroupLinker.renameIfNeeded's own ContentResolver query, not here.
```
Compressed to: `// The current name is always resolved; whether it differs is decided by renameIfNeeded.`

## app/src/test/java/org/kysecurity/mail/mail/AddressTextTest.kt
### `class AddressTextTest {`
```
// A display name is attacker-controlled and is authenticated by nothing: DKIM,
// SPF and DMARC all validate the domain a message was sent from, never the
// human-readable label in front of it. So this arrives intact and aligned:
//
//     From: "Bob <bob@corp.com>" <evil@attacker.tld>
//
// Reply/Reply All/Forward feed from this extractor and carry the quoted
// original, so picking the wrong address out of a From header sends a thread to
// a party who never sent it.
//
// These six vectors are shared verbatim with the webmail
// (frontend/src/lib/addressText.test.ts) and Linux (tests/qml/tst_AddressText.qml)
// clients, so all three agree that the real address is the LAST angle-addr.
```
Compressed to: `// The real address is the LAST angle-addr; vectors are shared with the webmail and Linux clients.`
### `@Test`
```
    // The bug in the old first-match rule: a display name dressed up as an
    // angle-addr won, so the reply went to Bob when the mail genuinely came
    // from the attacker.
```
### `@Test`
```
    // Not address-shaped is not an address. The old rule returned the raw value,
    // which put a display name into a recipient field.
```

## app/src/test/java/org/kysecurity/mail/mail/MailRepositoryTest.kt
### `@Test`
```
    /**
     * The self-heal. A since=0 fetch returns the server's whole window, but an older relay labels
     * it `delta: true`, so pruning used to be skipped and a removal the device never received (its
     * one-shot `removed` notification went to another poller, or to a response that never arrived)
     * stayed in the inbox forever. Mail deleted on the web is exactly that case.
     */
```
### `@Test`
```
    /** Pruning on a full window must not cost us the bodies of entries the window reports as
     *  `updated` — those entries never carry one, so the merge still has to win. */
```
### `@Test`
```
    /** A cursor-based (partial) delta must keep pruning to itself — it only ever describes what
     *  changed, so anything it doesn't mention is still legitimately in the mailbox. */
```
### `@Test`
```
    /**
     * An "updated" delta entry never carries a body. With no local row there is nothing to merge
     * into, and storing the entry anyway created a row whose empty body was indistinguishable from a
     * client-protected message — so the detail view asserted "this message is end-to-end encrypted"
     * about mail the server had decrypted and previously shown. Skipping it is correct: we do not
     * have this message, and a metadata-only delta is not a delivery of it. The forced daily full
     * snapshot brings it in with its body.
     */
```

## app/src/test/java/org/kysecurity/mail/mail/PhishingFlagTest.kt
### `class PhishingFlagTest {`
```
// The $Phishing IMAP keyword is how the server tells this client a message
// impersonates KyPost (backend/internal/processor/phish_scan.go). The warning
// bar in EmailDetailActivity reads it through this predicate.
//
// Advisory only: the links it warns about are already refused by
// SAFE_LINK_SCHEMES, whether or not the server ever flagged the message.
```
Compressed to: `// The $Phishing keyword is set by the server (backend/internal/processor/phish_scan.go).`
### `@Test`
```
    // IMAP keywords are case-insensitive, so a server may echo back a different
    // case than the one the poller set. A case-sensitive check would silently
    // drop the warning on exactly the mail it exists for.
```

## app/src/test/java/org/kysecurity/mail/mail/QuotedHtmlSanitizerTest.kt
### `class QuotedHtmlSanitizerTest {`
```
/**
 * The compose editor is a JavaScript-enabled WebView with a bound `@JavascriptInterface`, and
 * `setHtml` assigns straight to `innerHTML`. A `<script>` inserted that way does not run, but event
 * handler content attributes on inserted elements do — so quoting a sender's message into a reply
 * handed them read and write access to the message the user was about to send.
 *
 * These are the constructs that must not survive the quote.
 */
```
### `@Test`
```
    /**
     * Images are dropped entirely, not merely stripped of their handlers.
     *
     * `Safelist.relaxed()` permits `<img src="http://…">`, and the composer is a WebView with
     * network access and JavaScript enabled — so quoting a sender's message into a reply fired
     * their tracking beacon while the reply was being written. The reader blocks remote content
     * unconditionally until the user opts in per message; the composer, which has no such opt-in,
     * has to be at least as strict.
     */
```

## app/src/test/java/org/kysecurity/mail/mail/RelayMailSourceTest.kt
### `@Test`
```
    /**
     * A since=0 fetch asks for the whole window, and an older relay answers `delta: true` all the
     * same (it treats any `since` at all as a delta request). Only this layer knows what it sent,
     * so it is what tells the cache the response is complete enough to prune against.
     */
```
### `@Test`
```
    /**
     * The bytes must survive a body that only yields one okio segment per read, which is what a
     * real socket does. `readBounded` called `read` once and discarded the returned count, so every
     * attachment over 8 KiB arrived truncated and was still reported as Success. The existing
     * download tests all used `Buffer`-backed fixtures, whose `read` has no segment limit, so none
     * of them could fail. See [streamingResponse].
     */
```
### `private fun readBoundedFrom(bytes: ByteArray, limit: Long): ByteArray {`
```
    /** Drives [readBounded] directly with a small limit rather than allocating the real 25 MB bound
     *  twice per assertion — the logic under test is the boundary, not the constant. Bodies go
     *  through [streamingResponse] so they read one segment at a time like a real socket. */
```
Compressed to: `/** A small limit stands in for the real 25 MB bound; bodies read one segment at a time. */`
### `val oversized = ByteArray(10_001) { (it % 251).toByte() }`
```
        // One byte past the bound. readBounded used to return the prefix, and downloadAttachment
        // wrapped it in Success — so an oversized attachment was saved to Downloads, and carried
        // into a forward, as a silently corrupt file. There is no checksum on this path to catch it.
```
### `var called = false`
```
        // A pairing saved by a build predating NativePairingDeepLinkParser's https gate. Every
        // request built from it carries X-Kypost-Device-Secret, so it must not be attempted —
        // and it must fail as a named BadRequest, not as an opaque platform-level network error.
```
Compressed to: `// A pairing saved before the https gate existed; its requests carry X-Kypost-Device-Secret.`
### `@Test`
```
    /** The backend returns this when a client-protected account asks the server to sign or
     *  encrypt. Before this mapping it fell through to "Mail relay request failed (409)". */
```
### `@Test`
```
    /** A 409 without the marker must not inherit PGP wording — nothing else this app calls
     *  returns 409 today, but the mapping shouldn't assume that forever. */
```
### `@Test`
```
    /** Both refusals are 409 and are told apart by which field is present. A client-custody
     *  account must keep resolving to ClientSideNeeded — offering it a pickup-link dialog would
     *  answer a question it never got to ask, and no re-send from this device can fix it. */
```
### `@Test`
```
    /** An unrecognized 409 must not become a pickup prompt, and must not show the user raw JSON. */
```
### `@Test`
```
    /** A 409 whose keylessRecipients is present but empty carries no addresses to name in the
     *  dialog, so it cannot drive the confirmation flow. */
```
### `@Test`
```
    /** 502 bodies are plain text and say which of two things happened — SMTP failed, or every
     *  pickup link failed to deliver. Both mean nothing was sent, and the second is invisible
     *  under a fixed "Upstream IMAP/SMTP failure" string. */
```
### `@Test`
```
    /** The confirmed re-send must differ from the refused attempt in exactly one field. The
     *  Activity achieves this by holding the same MailDraft and calling .copy() (Task 8); this
     *  pins the wire-level property that makes it safe — a rebuilt message could differ subtly,
     *  and the recipients who *do* have keys would get something other than what was refused. */
```
### `@Test`
```
    /** A 200 with a non-empty warning is a success with a notice — the message was sent. It must
     *  never map to a failure, which would invite a retry that duplicates the message. */
```
### `@Test`
```
    /** A missing or non-numeric Retry-After must not be reported as "retry now" — null means the
     *  caller renders a generic "try again later". */
```
### `@Test`
```
    /** Drafts carry no crypto semantics — the server's draft handler ignores these fields — so
     *  sending them would claim a choice the user did not make at draft-save time. The webmail
     *  handoff saves a draft from a composition whose Encrypt toggle was on, so this is a live
     *  path, not a hypothetical.
     *
     *  Decoded into the DTO rather than asserted on the raw body string (matches
     *  resendWithFallback_differsOnlyInAllowPickupFallback above): a raw `!sent.contains("encrypt")`
     *  would fail spuriously if a fixture subject or body ever happened to contain that word. */
```
### `@Test`
```
    /**
     * The client-encrypted send posts pre-built ciphertext to a different endpoint entirely.
     *
     * `sentCopyEncrypted` is asserted true because it is an assertion *about the bytes*: the server
     * silently drops a copy that does not claim it, so sending false would quietly cost the user
     * their Sent folder. The outer subject must be the placeholder — the real one rides inside the
     * ciphertext, and putting it here would hand the server the very thing this path protects.
     */
```
### `@Test`
```
    /**
     * 403 is the send-as / From-binding refusal, and its body is plain text naming the problem.
     *
     * `mapErrorCode` had no 403 branch, so every endpoint degraded it to "Mail relay request failed
     * (403)" — discarding the one sentence that tells the user their From is not authorized. Fixed
     * for the whole class rather than at this one call site.
     */
```

## app/src/test/java/org/kysecurity/mail/mail/RelayModelsSerializationTest.kt
### `fun relayInboxResponseDto_decodesKeywordsArray() {`
```
    // The server sends the message's real IMAP keywords, including the $Phishing
    // flag the anti-phishing warning bar reads. This DTO ignored the field
    // entirely, so keywords were synthesised from `label` alone and a
    // server-set keyword could never reach the UI.
```

## app/src/test/java/org/kysecurity/mail/mail/Run4SanitizerMxssProbeTest.kt
### `class Run4SanitizerMxssProbeTest {`
```
/**
 * mXSS battery for [QuotedHtmlSanitizer].
 *
 * The composer is a JavaScript-enabled WebView with a bound `@JavascriptInterface` whose
 * `exportHtml` feeds draft save and send, and its `setHtml` assigns straight to `innerHTML`. This
 * sanitizer is the only control between a sender's HTML and that assignment, so the question that
 * matters is not "does jsoup strip handlers" but "does jsoup's *serialized output* re-parse into
 * something executable in Blink" — the classic mutation-XSS shape.
 *
 * Two properties are asserted per payload: nothing executable survives, and the output is stable
 * under re-sanitization. Instability is the mXSS signature: a sanitizer whose output differs from
 * its input's fixed point disagrees with itself about the parse, which is exactly the disagreement
 * an attacker exploits against a second parser.
 */
```
### `private fun executableConstructsIn(sanitized: String): List<String> {`
```
    /**
     * Re-parses the sanitized output the way a browser would and reports anything executable.
     *
     * Structural, not a regex over the serialized string. A regex cannot tell `onerror=` inside a
     * quoted `title` attribute (inert) or inside escaped text (inert) from a real event-handler
     * attribute, and both shapes occur throughout this battery — so a string-level detector reports
     * false positives on exactly the payloads it exists to judge.
     */
```
Compressed to: `/** Re-parses the output as a browser would: a regex cannot tell inert markup from live. */`
### `@Test`
```
    /**
     * Already-escaped markup must survive as escaped markup, not be unwrapped into live tags.
     *
     * This shape also exercises the catch-all fallback in [QuotedHtmlSanitizer], which unescapes
     * entities and re-escapes them; getting the order wrong there would turn quoted text back into
     * parsed elements on the way into a JavaScript-enabled WebView.
     */
```

## app/src/test/java/org/kysecurity/mail/mail/Run4ScopedCursorProbeTest.kt
### `class Run4ScopedCursorProbeTest {`
```
/**
 * Regression test for [MailCursorStore]'s scope-key separation.
 *
 * `cursorValue(folder)` and `resyncValue(folder)` are two [ScopedValue]s over the same DataStore.
 * They used to share one scopeKey, and [ScopedValue.set] writes the scope alongside its own value —
 * so writing the resync stamp re-stamped the scope over a *stale cursor* and re-authorised it for a
 * new subscriber, which is exactly the opposite of ScopedValue's stated contract. After re-pairing,
 * a relay that answered the first `/api/inbox` with a blank cursor (a supported case
 * `RelayMailSourceTest.nonDeltaLegacyResponse_stillParsesAsFullSnapshot` exercises) made the client
 * put the *previous* relay's cursor token on the wire to the new one.
 */
```

## app/src/test/java/org/kysecurity/mail/push/MfaAuthenticatorAvailabilityTest.kt
### `class MfaAuthenticatorAvailabilityTest {`
```
/**
 * The fail-open boundary on [MfaApprovalActivity]'s authentication gate.
 *
 * Approving a sign-in is the highest-value action in this app, and the screen is deliberately
 * exempt from the app lock — so "no authenticator is available" is the one condition that lets both
 * buttons go live untouched. It has to mean exactly that, and nothing adjacent to it.
 */
```
### `@Test`
```
    /**
     * The regression this file exists for. A sensor that is merely busy, or a status the platform
     * could not determine, used to be read as "this device has no screen lock" and enabled approve
     * and deny with no authentication whatsoever — on a device that does have one.
     */
```
### `@Test`
```
    /** An unrecognised future status must take the prompt path, which fails closed via
     *  `onAuthenticationError`, rather than the fail-open path. */
```

## app/src/test/java/org/kysecurity/mail/push/MfaChallengePayloadParserTest.kt
### `@Test`
```
    /** A server that has not been updated must keep working — the screen degrades to naming what
     *  it does not know, rather than the challenge being rejected. */
```
### `@Test`
```
    /** matchDigits drives a tap target, so nobody who can reach the push channel gets to put
     *  arbitrary text on a button. Width is the server's choice within a sane range — see
     *  [MfaChallengePayloadParser.MATCH_DIGITS_MAX_LENGTH]. */
```
### `@Test`
```
    /** A server that widens its value space must not have its digits silently discarded by an
     *  already-shipped client — that would disable approval outright, since there is no longer a
     *  bare Approve button to fall back to. */
```
### `@Test`
```
    /**
     * The challenge id becomes a key in a SharedPreferences XML file, written with a synchronous
     * `commit()` on the push-delivery thread, and every display field around it was already
     * length-capped. `isBlank()` was the only check standing between a hostile relay and an
     * arbitrary-length one — a disk-fill and a delivery-thread stall through an input path that was
     * being validated for the fields that only reach a TextView.
     */
```

## app/src/test/java/org/kysecurity/mail/push/MfaChallengeTrackerTest.kt
### `class MfaChallengeTrackerTest {`
```
/**
 * Covers the freshness window only. The storage half moved to SharedPreferences (so a challenge
 * survives the process death that FCM delivery routinely causes) and is exercised by the
 * instrumented `MfaChallengeTrackerPersistenceTest`.
 */
```
Compressed to: `/** Freshness only; storage is covered by instrumented MfaChallengeTrackerPersistenceTest. */`

## app/src/test/java/org/kysecurity/mail/push/MfaNumberMatchTest.kt
### `@Test`
```
    /**
     * The whole control. A challenge without a full choice set cannot be approved, so the caller
     * gets null and must offer Deny only — not a bare Approve that sends no number, which the
     * server refuses while spending one of the challenge's three attempts.
     */
```
### `@Test`
```
    /** The client never invents a wrong answer. Decoys derived on-device from the challenge id were
     *  computable by anyone who knew the id. */
```
### `@Test`
```
    /**
     * Width comes from the server, not a client constant. Two digits is only 100 values, so
     * widening it is the obvious next hardening — and pinning the width here would have made every
     * deployed client silently discard the field the moment the server did.
     */
```
### `@Test`
```
    /** Mixed widths are a malformed choice set, not a partial one — a tile that is visibly a
     *  different shape from the others is a free elimination. */
```
### `@Test`
```
    /** The answer must not sit in a predictable slot; that is a free guess for anyone who has seen
     *  the screen once. */
```

## app/src/test/java/org/kysecurity/mail/push/MfaResponseClientTest.kt
### `@Test`
```
    /** 400 is "wrong number, challenge still live" — distinct from 401, and the old `else` branch
     *  reported it as the opaque "Failed to respond (400)". */
```
### `@Test`
```
    /** 429 means the attempt budget is spent and the challenge is dead even with the right number. */
```

## app/src/test/java/org/kysecurity/mail/push/NativePairingDeepLinkParserTest.kt
### `val result = NativePairingDeepLinkParser.parse(`
```
        // A stale cached QR image from before the per-device-secret migration may still carry a
        // hash= param; it must simply be ignored, not rejected, since it's harmless and the
        // pairingToken alone is what actually gates registration.
```
Compressed to: `// A stale QR from before the per-device-secret migration may carry hash=; ignore it.`

## app/src/test/java/org/kysecurity/mail/push/NativeRegistrationClientTest.kt
### `class NativeRegistrationClientTest {`
```
/**
 * Test 7, carried over from the original 2b handoff and finally placed.
 *
 * Rebinding an existing `deviceId` returns **409** unless the current device secret is sent, and the
 * reason the server requires it is not cosmetic: without it a stolen session could take over an
 * existing device row, keeping its `MFAApprover` status and redirecting that user's push. The
 * FCM-token-refresh flow re-registers, so this is the ordinary path, not an edge case.
 *
 * It also matters to enrollment specifically. The server carries `enrollmentPublicKey` and
 * `encryptionEnrolled` forward across re-registration on both branches — which is worth nothing if
 * re-registration itself 409s.
 */
```
### `@Test`
```
    /**
     * A first pairing has no secret yet — it is what this call mints. Sending an empty or absent
     * credential must not be confused with sending a wrong one.
     */
```
### `@Test`
```
    /** A half-known pairing — an id with no readable secret, which the credential gate produces
     *  while the app is locked — must not send a device id on its own. The server reads that as a
     *  rebind attempt with no credential. */
```
### `@Test`
```
    /** 409 is a distinct, actionable outcome — "this device row belongs to a credential you did not
     *  send" — and must not read as a generic transport failure. */
```

## app/src/test/java/org/kysecurity/mail/push/PairingDeepLinkConsumptionTest.kt
### `class PairingDeepLinkConsumptionTest {`
```
/**
 * A pairing deep link must be consumed exactly once, on **every** path that consumes one.
 *
 * `onNewIntent` cleared `intent.data` after consuming it and carried a paragraph explaining why: an
 * attacker's cancelled "replace your pairing with evil.tld" prompt resurfacing later, with no link
 * tap to explain it, after the user has been trained by a legitimate one. `onCreate` did not — and
 * `onCreate` is the path that is actually reached first, because a browser or a co-installed app
 * delivers `kypost://native-pair` through `PushPairingLinkActivity` -> `startActivity`. `getIntent()`
 * then keeps returning that Intent with its data intact, so every rotation, dark-mode toggle and
 * restore-after-eviction re-raised the prompt. One call site had the guard and the other did not.
 *
 * **A source-level assertion, deliberately.** The first version of this was an instrumented test
 * that launched the Activity with a deep link and asserted the cleared Intent. It could not be made
 * to pass: the Activity never reached RESUMED under `ActivityScenario`, and the property is a
 * lifecycle detail that a harness has to reproduce exactly to say anything about. This says less —
 * it cannot prove the Intent is cleared at runtime — but what it does say, it says reliably, and it
 * is the thing that actually regressed: a second consumption site added without the guard beside
 * it. Same reasoning, and the same crude-reader technique, as `SourceRulesTest`.
 */
```
Compressed to: `/** A source-level check, not a runtime one: it reads PushPairingActivity.kt as text. */`

## app/src/test/java/org/kysecurity/mail/push/PairingOriginTest.kt
### `class PairingOriginTest {`
```
/**
 * Regression tests for the cross-origin registration URL hole.
 *
 * A QR could name a legitimate server in `srv` — which is what the pairing confirmation dialog
 * shows the user — while pointing `reg` at an attacker. Only https was checked, and
 * `https://evil.example` passes that trivially. The registration endpoint is where the device
 * secret is minted, so this leaked the subscriber ID, pairing token and FCM token behind a
 * trusted-looking hostname, and poisoned the TOFU pin on the way out.
 */
```
### `@Test`
```
    // --- Second gate: the resolver, for pairings persisted by an older build -------------------

```

## app/src/test/java/org/kysecurity/mail/push/PairingUrlHostTest.kt
### `class PairingUrlHostTest {`
```
/**
 * The pairing confirmation dialog is a trust prompt, and it used to render the raw `srv` string
 * straight from the deep link. A URL with userinfo reads as the trusted host on a wrapped dialog
 * while every request goes somewhere else — and `kypost://native-pair` is BROWSABLE, so any web
 * page can fire it.
 */
```
### `@Test`
```
    /** sameOrigin is also reached for pairings persisted by an older build, which is exactly where
     *  a userinfo URL saved before this check existed would still be sitting. */
```
### `@Test`
```
    /**
     * Validation and connection now use the *same* parser (OkHttp's `HttpUrl`).
     *
     * They used to differ: every check ran on `java.net.URI` while the request was built from
     * `HttpUrl`. Two parsers either side of a trust decision is the classic shape of a
     * parser-differential bypass, and there was no reason for it.
     */
```

## app/src/test/java/org/kysecurity/mail/push/PinnedOrFallbackCallFactoryTest.kt
### `class PinnedOrFallbackCallFactoryTest {`
```
/**
 * The distinction this class exists for: "no pin yet" and "the pin is gone" are different states.
 *
 * The implementation this replaces was `pinnedProvider() ?: fallback`, which answered both with an
 * unpinned client. Every request from this app carries `X-Kypost-Device-Secret`, so the second case
 * was a permanent, silent downgrade to bare system-CA trust — triggered by anything that lost the
 * pin, most plausibly a reset of the encrypted store that holds it.
 */
```
### `@Test`
```
    /** The refusal has to arrive through the same failure path every other network error does, or
     *  callers will not map it to a user-facing message. */
```

## app/src/test/java/org/kysecurity/mail/security/AppLockManagerTest.kt
### `@Test`
```
    /**
     * The threshold is the user's, not a constant. It used to be a hardcoded ten with no
     * off-switch, which made "borrow the phone for an afternoon" a way to permanently destroy mail
     * and contacts the app deliberately keeps no backup of.
     */
```
### `assertTrue(manager.attemptPin("000001".toCharArray()) is UnlockAttemptResult.Rejected)`
```
        // Still throttled, just not destructive.
```
### `@Test`
```
    /** A wipe that fails a step must not be reported as a completed wipe: the UI would otherwise
     *  show the same clean first-run state while the cached mail is still on disk. */
```
### `@Test`
```
    // --- Lockout enforcement lives in the manager, not in the view -----------------------------

```
### `assertTrue(manager.attemptPin("482913".toCharArray()) is UnlockAttemptResult.Rejected)`
```
        // The throttle is not a "wrong PIN" penalty that a lucky guess can skip past — while it is
        // active nothing is verified at all.
```
### `@Test`
```
    // --- Background grace window --------------------------------------------------------------

```
### `assertTrue(manager.isLockedNow())`
```
        // The whole point: nothing called lockNow(). KyPostApp's Handler runs on uptimeMillis,
        // which does not advance in deep sleep, so on a pocketed phone it may not have fired.
        // Before this existed, `locked` stayed false for the entire time the app was backgrounded,
        // and PushNotificationDispatcher put the sender and subject on the lock screen in full.
```
### `assertTrue(gatedManager.cachedCredentialKeys() == null)`
```
        // The credential gate is meant to withhold the device secret from a backgrounded app;
        // holding the keys until something called lockNow() left it open indefinitely.
```
### `@Test`
```
    // --- Credential keys ----------------------------------------------------------------------

```
### `@Test`
```
    /**
     * The opened PGP private key is plaintext held for one unlock session, so the app locking is
     * the whole of its lifetime — the same window `credentialKeys` above is bound to.
     *
     * Unconditional, not gated on the lock being enabled: a manager with the lock off must still
     * drop it, or turning the lock off would keep the key alive indefinitely.
     */
```
### `@Test`
```
    // --- Biometric unlock -----------------------------------------------------------------------

    /**
     * A PIN unlock seals the derived keys **whether or not the credential gate is on**, because
     * sealing is what gives the next biometric unlock something real to unwrap. Without it,
     * `unlockWithBiometric` was a bare boolean: nothing cryptographic depended on the fingerprint,
     * so hooking the success callback unlocked the app with no secret ever produced.
     */
```
### `@Test`
```
    /** Sealing is a consequence of a *verified* PIN, never of an attempt. */
```
### `@Test`
```
    /**
     * The wart this closes: a biometric-only session used to run with the credential gate
     * permanently shut, so no authenticated relay call could be made and no MFA challenge could be
     * answered — for the user whose whole point is that they use the fingerprint reader.
     */
```
### `@Test`
```
    /**
     * The lockout ladder is not something a fingerprint steps over.
     *
     * `unlockWithBiometric` checked nothing at all: it unlocked and called `resetFailedAttempts()`,
     * so a biometric presented mid-ladder cleared both the accumulated delay and the progress
     * toward the wipe threshold — an escape hatch from the throttle, handed to exactly the attacker
     * `setInvalidatedByBiometricEnrollment(true)` is aimed at, by omission rather than by decision.
     */
```
### `@Test`
```
    /** ...and is allowed again once it has run out. */
```
### `@Test`
```
    /**
     * A [AppLockManager.DecisionToken] is only honoured by the manager that issued it.
     *
     * The constructor used to be `internal`, which is module-visible — and this app is one module,
     * so every file could mint one while the KDoc claimed the type system prevented exactly that.
     * There is no way to write the forgery test any more, which is the point; this asserts the
     * remaining hole (a token from a *different* manager) is closed too.
     */
```
### `@Test`
```
    /** Symmetric with the PIN path: with the gate off nothing needs the key, so nothing holds it. */
```
### `@Test`
```
    /**
     * Changing the PIN has to re-seal, or the blob keeps the *old* PIN's keys — and with the
     * credential gate on, the next biometric unlock would hand out a key that no longer unwraps
     * `deviceSecret`, so every authenticated call would fail behind a UI still reading "Paired".
     */
```
### `@Test`
```
    /**
     * The reason [AppLockManager.deriveAndCacheCredentialKeys] returns [UnlockAttemptResult] rather
     * than a `Boolean`: this path runs the same wipe threshold as every other PIN check, and
     * collapsing the outcome to `false` meant the settings screen reported a completed destructive
     * wipe as "wrong PIN" and carried on against a store that no longer existed.
     */
```
### `@Test`
```
    /**
     * Concurrent PIN checks must not lose an increment of the failed-attempt counter.
     *
     * [AppLockState.incrementFailedAttempts] is a read-modify-write, and all three public entry
     * points hop to the multi-threaded [kotlinx.coroutines.Dispatchers.Default] pool, so without the
     * manager's own mutex two checks in flight together both read `n` and both write `n + 1` — the
     * lockout ladder and the wipe threshold silently under-count, which is an unthrottled parallel
     * guessing window.
     *
     * The clock advances an hour on every read so no lockout is ever in force; what is under test is
     * the counter, not the delay ladder. Attempts stay below [LockoutPolicy.DEFAULT_WIPE_THRESHOLD] so the
     * wipe branch does not swallow the last one.
     */
```
Compressed to: `/** Clock jumps an hour per read, so no lockout applies and no wipe triggers. */`
### `@Test`
```
    /**
     * An unevaluable verifier is not a wrong PIN.
     *
     * `PinHasher.pepperKey` used to *create* a key whenever it found none, so an OS-level Keystore
     * reset silently produced a different pepper and every subsequent correct PIN verified as
     * false. Ten of those hit [LockoutPolicy.DEFAULT_WIPE_THRESHOLD] and destroyed the user's mail,
     * contacts and pairing — in response to an event they neither caused nor could avoid.
     */
```
### `@Test`
```
    /** The same guarantee on the settings/MFA entry point, which runs the identical accounting. */
```
### `@Test`
```
    /**
     * A correct PIN whose *credential* key cannot be derived is still a correct PIN.
     *
     * The two peppers are separate Keystore aliases on purpose, so the wrapping key can be lost
     * without the verifier being lost. Letting a derivation failure propagate out of the success
     * path would have turned that into an unlock failure — and, on the settings screen, into
     * another counted attempt.
     */
```
### `assertNull(gatedManager.cachedCredentialKeys())`
```
        // The gated secret simply stays unavailable, exactly as after a biometric-only unlock.
```

## app/src/test/java/org/kysecurity/mail/security/AttachmentActionTest.kt
### `@Test`
```
    /**
     * The regression this exists for: a tap used to mean SAVE_TO_DOWNLOADS whenever protection was
     * off, which is the default. One unprompted tap therefore wrote decrypted mail into shared
     * storage outside the sandbox, and [EphemeralAttachmentBytes] — the whole TTL-and-zeroing
     * apparatus — was unreachable for almost every user.
     */
```

## app/src/test/java/org/kysecurity/mail/security/CredentialCipherTest.kt
### `private class FixedPepper(private val keyBytes: ByteArray = "test-pepper".toByteArray()) : CredentialPepper {`
```
/**
 * A stand-in for [KeystoreCredentialPepper] with a fixed key, since a JVM unit test has no
 * AndroidKeyStore. What matters here is that the peppered and unpeppered keys genuinely differ and
 * that a different pepper cannot unwrap — which is the whole point of the mechanism.
 */
```
Compressed to: `/** Stand-in for [KeystoreCredentialPepper]: a JVM unit test has no AndroidKeyStore. */`
### `val tampered = WrappedSecret(`
```
        // The old `wrapped.copy(...)` mutated `wrapped.ciphertext` in place and then "copied" it,
        // so it was testing the same array twice over. Explicit, and no longer relying on a
        // generated `copy` that WrappedSecret deliberately no longer has.
```
### `val salt = CredentialCipher.randomSalt()`
```
        // The migration path: a v1 blob was wrapped with the bare PBKDF2 output and must stay
        // readable so rewrapPairingIfNeeded can move it onto the peppered key.
```

## app/src/test/java/org/kysecurity/mail/security/CredentialEnvelopeTest.kt
### `class CredentialEnvelopeTest {`
```
/**
 * The envelope is exercised here with a plain JCE keypair rather than the AndroidKeyStore one,
 * because the Keystore's private key cannot be used without a live biometric prompt — which no
 * automated test can satisfy. What this suite pins is the part that would silently differ between
 * the two: the OAEP parameters. [CredentialEnvelope] hands the *same* [javax.crypto.Cipher]
 * configuration to both sides, so a round trip that works here works on-device.
 */
```
Compressed to: `/** Plain JCE keypair: the Keystore key needs a live biometric prompt. Pins the OAEP params. */`
### `assertArrayEquals(keys.legacy.encoded, opened.legacy.encoded)`
```
        // The legacy key travels too. Dropping it would leave a pre-pepper wrap unreadable after a
        // biometric unlock, so rewrapPairingIfNeeded could never migrate it.
```
### `@Test`
```
    /** A blob sealed under a key that is now gone reads as "nothing sealed", never as a crash: the
     *  caller's only sane response is to fall back to the PIN, and an exception on the unlock
     *  screen is not that. */
```
### `@Test`
```
    /** Plaintext of the wrong length is a corrupted envelope, not two keys — splitting it anyway
     *  would hand out a short AES key that unwraps nothing and reads as a wrong PIN. */
```

## app/src/test/java/org/kysecurity/mail/security/LockoutPolicyTest.kt
### `@Test`
```
    /**
     * The wipe used to be a hardcoded ten attempts with no off-switch — an effective denial of
     * service for anyone with an afternoon's access to the phone, against data the app
     * deliberately keeps no backup of.
     */
```
### `@Test`
```
    /**
     * The point of the longer ladder: the default threshold has to be out of reach of someone who
     * borrows the phone, not merely inconvenient. Eighty minutes was the old figure.
     */
```

## app/src/test/java/org/kysecurity/mail/security/PinHasherTest.kt
### `private val pepper = CredentialPepper { derived -> derived.map { (it + 1).toByte() }.toByteArray() }`
```
    /** The production pepper is an AndroidKeyStore HMAC key, which a JVM test has no access to —
     *  same reason [CredentialCipher]'s tests inject one. Any deterministic transform exercises the
     *  peppering path; what matters here is that a pepper participates at all. */
```
Compressed to: `/** The real pepper is a Keystore HMAC key; any deterministic transform exercises the path. */`
### `@Test`
```
    /** The peppered verifier must not equal the bare PBKDF2 one, or the pepper is not reaching the
     *  stored value and an extracted hash stays offline-crackable. */
```
### `@Test`
```
    /** A v1 hash written by an older install still has to verify, so the upgrade path in
     *  `AppLockStore.verifyPin` can recognise the correct PIN before rewriting it peppered. */
```

## app/src/test/java/org/kysecurity/mail/security/PinPolicyTest.kt
### `assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("4829137056".toCharArray()))`
```
        // The old flow hardcoded exactly 6; length is the only lever the user has against the
        // keyspace, so a longer PIN must not be rejected.
```
### `assertEquals(PinPolicy.Result.TooShort, PinPolicy.validate("482913".toCharArray()))`
```
        // 6 and 7 digits were accepted before the minimum was raised: PBKDF2 iterations cannot
        // defend a 10^6 keyspace, so the floor moved rather than the iteration count.
```
### `listOf("12121212", "11223344", "12341234", "19801980", "14725836").forEach {`
```
        // The lock throttles hard and can wipe, so the guess budget is small — every one of these
        // would have been inside it.
```

## app/src/test/java/org/kysecurity/mail/security/Run4MfaCredentialGateTest.kt
### `private class GateState(`
```
/**
 * Regression tests for the credential-gate MFA path.
 *
 * Covers the state `MfaApprovalActivity.promptAppLockPin` lands in when the credential PIN gate is
 * on and the app is locked — which its own KDoc calls the normal case for an MFA challenge. A
 * notification tap does not unlock the app, so `cachedCredentialKeys()` correctly returns null
 * throughout; the key the just-authenticated decision needs comes from `credentialKeysForDecision()`
 * instead. Before that split existed, every gated approve *and deny* died locally in
 * `MfaResponseClient` with "Device is not registered yet" and no request ever left the device — a
 * user who knew a sign-in was hostile could not deny it.
 */
```
### `@Test`
```
    /**
     * The exact call MfaApprovalActivity.promptAppLockPin makes when credentialGateNeedsPin() is
     * true: the PIN verifies, the key is derived, and the decision is sendable — while the app stays
     * locked, so nothing else in the process gains access to the mailbox.
     */
```
### `assertTrue("fresh process must start locked", m.isLockedNow())`
```
        // Fresh process, lock enabled -> AppLockManager starts locked, exactly as an FCM-delivery
        // process does.
```
### `assertNotNull("a verified decision must mint a token", token)`
```
        // MfaApprovalActivity captures this and hands it to MfaResponder, which passes it to
        // PushRepository.pairingForAuthenticatedCall(keys). The token is the ONLY way to obtain
        // it: the accessor this replaced was public, unguarded and returned the cached key to any
        // caller that asked, which made it the credential gate's own bypass.
```
### `assertTrue("the app stays locked", m.isLockedNow())`
```
        // ...and none of that unlocks the app. A notification tap must not open the mailbox, and
        // background sync must still be withheld from the credential.
```
### `@Test`
```
    /** A wrong PIN derives nothing, so there is no decision key to capture. */
```
### `@Test`
```
    /** The contrast: the unlock screen's path clears _locked first, so the same key is usable. */
```
### `@Test`
```
    /**
     * A biometric-only session no longer needs the PIN prompt at all.
     *
     * This used to assert the opposite — "biometric unlock derives no PIN key" — because
     * `unlockWithBiometric()` set a flag and produced nothing. It now opens the keys a previous PIN
     * unlock sealed, so `credentialGateNeedsPin()` is false and the gated credential is usable.
     */
```
### `@Test`
```
    /**
     * The branch `credentialGateNeedsPin()` still exists for: unlocked, gate on, and no key —
     * reached when the credential pepper is gone, which is a lost wrapping key rather than a wrong
     * PIN. The MFA prompt has to keep working there.
     */
```

## app/src/test/java/org/kysecurity/mail/security/ScreenshotFlagDefaultTest.kt
### `class ScreenshotFlagDefaultTest {`
```
/**
 * `-PallowScreenshots=true` strips `FLAG_SECURE` from every window in the app. It is meant to be
 * passed for one local build and never again, so this fails any build — CI included — that carries
 * it, rather than letting a screenshot build become the default one somebody ships from.
 */
```
Compressed to: `/** `-PallowScreenshots=true` strips `FLAG_SECURE` app-wide; no shipped build may carry it. */`

## app/src/test/java/org/kysecurity/mail/security/SecuritySessionResetTest.kt
### `@Test`
```
    /**
     * The load-bearing case: the caller's scope dies mid-change, and the reset must still run.
     *
     * This is the Hostile Location Protection toggle being interrupted by a Back press or a
     * rotation. The destructive work and the flag commit were already protected; the *reset* was
     * not, so the setting committed while the previous session's decrypted attachments and draft
     * stayed in the process.
     *
     * The outer scope deliberately uses a different dispatcher from the work context, because that
     * is what makes the continuation resume cancellably — the real pairing is
     * `Dispatchers.Main.immediate` outside and `Dispatchers.Default` inside. With one shared
     * dispatcher this bug is invisible.
     */
```
Compressed to: `/** The outer scope needs a different dispatcher from workContext, or the bug hides. */`
### `@Test`
```
    /** The ordinary path still works, and the reset runs after the change rather than beside it. */
```

## app/src/test/java/org/kysecurity/mail/security/SpkiPinnerTest.kt
### `private const val TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----`
```
// A real, valid self-signed X.509 certificate (subject/issuer CN=test), generated once with:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 3650 -subj "/CN=test"
// `sun.security.x509` internal JDK classes are not accessible from this project's unit-test JVM
// (JPMS blocks the `java.base` package export), so a hardcoded PEM stands in for in-process
// certificate minting. Only a genuine, parseable X509Certificate is required to exercise
// SpkiPinner.pinFor — how it was produced is not load-bearing.
```
Compressed to: `// Self-signed X.509 (CN=test) from: openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=test"`

## app/src/test/java/org/kysecurity/mail/security/UnrecoverableKeysetTest.kt
### `class UnrecoverableKeysetTest {`
```
/**
 * The predicate that decides whether an encrypted store is destroyed or a failure is propagated.
 *
 * Getting it wrong is expensive in both directions: too broad and a full disk deletes the user's
 * private key, too narrow and a store the app can never read again is never reset, so
 * `AppLockStore.isLockEnabled()` throws out of `SecurityGraph`'s constructor and out of
 * `LockedActivity.onCreate` — the app cannot start at all.
 *
 * It has been too narrow. Matching `javaClass.simpleName` against `"InvalidProtocolBufferException"`
 * missed every nested subclass, whose `simpleName` is its own. On API 31 the corrupted keyset
 * surfaces as `InvalidWireTypeException`, so the recovery never ran and seventeen other suites went
 * down with it. On API 34 the same corruption produced the base type and everything passed, which
 * is exactly how it stayed hidden.
 *
 * The stand-ins below mirror the shape of Tink's shaded types — a base class named
 * `InvalidProtocolBufferException` that extends `IOException`, with nested subclasses — because the
 * real ones live in a shaded package this code must not import.
 */
```
Compressed to: `/** The stand-ins below mirror Tink's shaded types, which this code must not import. */`
### `@Test`
```
    /**
     * The other direction, which matters more: a transient storage failure must NOT be treated as
     * an unreadable keyset. Deleting a credential the user cannot get back is not an acceptable
     * response to the disk being full for a second.
     */
```
### `@Test`
```
    /** A cause chain that loops must not hang the predicate. */
```

## app/src/test/java/org/kysecurity/mail/security/WipeDeregisterPinningTest.kt
### `class WipeDeregisterPinningTest {`
```
/**
 * The wipe's one outbound request must be pinned or must not happen.
 *
 * It went out **unpinned**. The wipe clears the pairing — and with it `KEY_TLS_PIN` and the pin
 * tripwire — before the deregister runs, so by the time
 * [org.kysecurity.mail.push.PinnedOrFallbackCallFactory] was asked for a client it read
 * `TlsPinState.NeverPaired`, the one state that legitimately falls back to bare system-CA trust.
 * `X-Kypost-Device-Secret` then travelled over an unpinned connection during the operation whose
 * whole premise is that the device is in hostile hands, quite possibly on the attacker's network.
 *
 * A JVM test, which is the point: the fix is that the client is built from a pin captured up front
 * rather than resolved from state that no longer exists, and "built from what, exactly" is
 * answerable without a device.
 */
```
Compressed to: `/** The deregister client is built from a pin captured before the wipe clears the pairing. */`

## app/src/test/java/org/kysecurity/mail/testing/FakeCalls.kt
### `internal class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {`
```
/**
 * Shared hand-rolled fakes for OkHttp's [Call.Factory], so a client can be exercised without a real
 * network call. This repo has no mocking framework and no MockWebServer dependency, and injecting a
 * [Call.Factory] rather than a concrete `OkHttpClient` is the seam every client here is built around.
 *
 * These lived as `private` top-level copies in each test file, which worked only while no two files
 * in the same package needed them. Kotlin compiles a top-level `private` class to a package-level
 * JVM name — `private` restricts visibility, not the emitted class name — so the second test file in
 * `org.kysecurity.mail.pgp` to declare `FakeCallFactory` failed to compile as a duplicate class. That was
 * papered over with per-file name prefixes (`BootstrapFakeCallFactory`, `RecipientKeyFakeCall`, …),
 * which left four near-identical copies under three naming conventions. One `internal` copy here
 * removes both problems: `internal` is module-wide, so any test in this source set can use it.
 */
```
Compressed to: `/** Shared OkHttp [Call.Factory] fakes; `internal` because top-level `private` still clashes. */`
### `internal class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {`
```
/**
 * [FakeCallFactory] that also captures each request body as a string.
 *
 * Separate from [FakeCallFactory] rather than folded into it because reading a body consumes it:
 * every GET-only test would pay for a capture it never inspects.
 */
```
Compressed to: `/** [FakeCallFactory] that also captures bodies; separate because reading a body consumes it. */`
### `internal fun response(`
```
/** Canned JSON response. Keeps the name the per-file copies used, so adopting this file is a
 *  deletion plus an import rather than a rewrite of every call site.
 *
 *  [headers] exists for the responses whose meaning is carried outside the body — `Retry-After` on a
 *  429 being the one this repo actually reads. */
```
Compressed to: `/** Canned JSON response; [headers] carries meaning outside the body, e.g. `Retry-After`. */`
### `internal fun streamingResponse(`
```
/**
 * A response whose body has the same read semantics as a real socket, for anything that reads bytes
 * rather than calling `.string()`.
 *
 * [response] above builds its body with `String.toResponseBody`, which is `Buffer`-backed — and
 * `Buffer.read(sink, byteCount)` copies `min(byteCount, size)` from itself in one call, with no
 * segment limit. A real network body is a `RealBufferedSource`, whose `read` fills at most one
 * 8 KiB segment per call and returns that. Code that calls `read` once and ignores the return value
 * therefore passes against [response] and silently truncates in production — which is exactly what
 * `RelayMailSource.readBounded` did to every attachment over 8 KiB.
 *
 * Wrapping a plain [okio.Source] in `okio.buffer` reproduces the real semantics, so a test written
 * against this fake fails when the loop is missing.
 */
```
Compressed to: `/** Body with real socket read semantics: one 8 KiB segment per read, unlike [response]'s Buffer. */`
