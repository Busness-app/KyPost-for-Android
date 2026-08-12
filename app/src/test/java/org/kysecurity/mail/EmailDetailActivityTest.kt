package org.kysecurity.mail

import org.kysecurity.mail.pgp.DecryptedBody
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.ReadOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
class EmailDetailActivityTest {

    @Test
    fun emailBodyToHtml_preservesPlainTextWhitespaceAndEscapesMarkup() {
        val html = emailBodyToHtml("one\t two\nthree < four", "plain")

        assertTrue(html.startsWith("<div class=\"kypost-plain-text\">") )
        assertTrue(html.contains("one\t two\nthree &lt; four"))
    }

    @Test
    fun emailBodyToHtml_respectsExplicitHtmlMode() {
        assertEquals("<p>hello</p>", emailBodyToHtml("<p>hello</p>", "html"))
    }

    @Test
    fun emailBodyToHtml_fallbackRecognizesEmailHtmlTags() {
        assertEquals("<center><p>hello</p></center>", emailBodyToHtml("<center><p>hello</p></center>", ""))
    }

    @Test
    fun isPlainTextBody_usesHtmlDetectionWhenModeIsMissing() {
        assertTrue(isPlainTextBody("a very wide line", ""))
        assertFalse(isPlainTextBody("<p>hello</p>", ""))
        assertTrue(isPlainTextBody("<user@example.com>", ""))
        assertTrue(isPlainTextBody("# Security Policy\nSee https://example.com", "html"))
        assertFalse(isPlainTextBody("<img src=\"cid:image\">", "html"))
        assertTrue(isPlainTextBody("# Security Policy\nSee the [advisory](https://example.com)", "html"))
    }

    @Test
    fun softWrapPlainText_addsInvisibleBreaksOnlyToLongTokens() {
        val wrapped = softWrapPlainText("short ${"a".repeat(40)}")

        assertEquals("short aaaaaaaaaaaaaaaa\u200Baaaaaaaaaaaaaaaa\u200Baaaaaaaa", wrapped)
        assertEquals("short text", softWrapPlainText("short text"))
    }

    @Test
    fun blockExternalResources_removesImageAndStyleResourceUrls() {
        val blocked = blockExternalResources(
            "<img src=\"https://example.com/a.png\"><div style=\"background:url(https://example.com/b.png)\">Hi</div>",
        )

        assertFalse(blocked.contains("https://example.com"))
        assertTrue(blocked.contains("Hi"))
    }

    private val darkPalette = ThemePalette(
        bg = "#1a1a1e",
        panel = "#252530",
        ink = "#d4c5e2",
        inkStrong = "#e8ddf5",
        accent = "#c29a72",
        line = "#404050",
        avatarGradientStart = "#c29a72",
        avatarGradientEnd = "#9a7450",
        avatarBorder = "#8f6b4a",
    )

    private val lightPalette = ThemePalette(
        bg = "#f5efe5",
        panel = "#fff8ee",
        ink = "#4c3d32",
        inkStrong = "#2d1f15",
        accent = "#c29a72",
        line = "#c5b29d",
        avatarGradientStart = "#c29a72",
        avatarGradientEnd = "#9a7450",
        avatarBorder = "#8f6b4a",
    )

    /** An email that only sets its own text color (the "black text on the app's default dark
     *  background" half of the reported bug) — the wildcard `!important` override must still win. */
    private val emailWithOwnTextColorOnly =
        """<div style="color:#000000">Hello, this text sets its own black color.</div>"""

    /** An email that sets both its own background and text color (the "black text on white,
     *  ignoring the app's theme" half of the reported bug). */
    private val emailWithOwnBackgroundAndTextColor =
        """<table bgcolor="#ffffff"><tr><td style="color:#000000">Hi</td></tr></table>"""

    @Test
    fun darkPalette_forcesTextAndBackgroundColorsWithImportant_overridingAnyEmailStyle() {
        val html = buildEmailBodyHtml(emailWithOwnTextColorOnly, darkPalette, monoFontFace = "", isDark = true)

        assertTrue(html.contains("body * {"))
        assertTrue(html.contains("color: ${darkPalette.inkStrong} !important;"))
        assertTrue(html.contains("background-color: transparent !important;"))
        assertTrue(html.contains("background-color: ${darkPalette.bg} !important;"))
        // The email's own markup must survive untouched — overriding happens via CSS, not by
        // stripping/rewriting the email's HTML.
        assertTrue(html.contains(emailWithOwnTextColorOnly))
    }

    @Test
    fun darkPalette_keepsLinksOnAccentColor_afterTheWildcardOverride() {
        val html = buildEmailBodyHtml(emailWithOwnBackgroundAndTextColor, darkPalette, monoFontFace = "", isDark = true)

        val wildcardIndex = html.indexOf("body * {")
        val linkRuleIndex = html.indexOf("body a, body a * {")
        assertTrue("link color override must come after the wildcard rule to win the cascade", linkRuleIndex > wildcardIndex)
        assertTrue(html.contains("color: ${darkPalette.accent} !important;"))
    }

    @Test
    fun lightPalette_doesNotForceOverridesAtAll() {
        val html = buildEmailBodyHtml(emailWithOwnBackgroundAndTextColor, lightPalette, monoFontFace = "", isDark = false)

        assertFalse(html.contains("body * {"))
        assertFalse(html.contains("!important"))
        // The plain (non-important) body rule from before this fix must still be present.
        assertTrue(html.contains("color: ${lightPalette.inkStrong};"))
        assertTrue(html.contains("background-color: ${lightPalette.bg};"))
    }

    @Test
    fun plainTextBody_wrapsLongLinesWithoutHorizontalOverflow() {
        val html = buildEmailBodyHtml(
            emailBodyToHtml("a".repeat(500), "plain"),
            lightPalette,
            monoFontFace = "",
            isDark = false,
        )

        assertTrue(html.contains("overflow-x: hidden;"))
        assertTrue(html.contains("min-width: 0;"))
        assertTrue(html.contains("max-width: 100%;"))
        assertTrue(html.contains("width: 100%;"))
        assertTrue(html.contains("word-wrap: break-word;"))
        assertTrue(html.contains("word-break: break-all;"))
    }

    @Test
    fun darkPalette_stripsImportantFromAnEmailThatDefendsItsOwnWhiteBackground() {
        val email = """<table style="background-color:#ffffff !important; color:#000000!important"><tr><td>Hi</td></tr></table>"""

        val html = buildEmailBodyHtml(email, darkPalette, monoFontFace = "", isDark = true)

        // The email's own !important must be gone (the property values it guarded, #ffffff/#000000,
        // are left in place — harmless once stripped of their importance, since body * still forces
        // transparent/inkStrong over them; it's specifically the token that let them out-rank our
        // override that must go). Our own override rules' !important (in the <style> block, before
        // <table>) is untouched and expected.
        val emailPortion = html.substringAfter("<table")
        assertFalse(emailPortion.contains("important", ignoreCase = true))
        assertTrue(emailPortion.contains("#ffffff"))
        assertTrue(emailPortion.contains("#000000"))
    }

    @Test
    fun lightPalette_leavesImportantInTheEmailUntouched() {
        val email = """<table style="background-color:#ffffff !important"><tr><td>Hi</td></tr></table>"""

        val html = buildEmailBodyHtml(email, lightPalette, monoFontFace = "", isDark = false)

        assertTrue(html.contains(email))
    }

    // ---- stripImportantFromCss: token removal within one declaration block ----

    @Test
    fun stripImportantFromCss_removesLowercaseImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !important"))
    }

    @Test
    fun stripImportantFromCss_isCaseInsensitive() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !IMPORTANT"))
    }

    @Test
    fun stripImportantFromCss_toleratesNoSpaceBeforeImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000!important"))
    }

    @Test
    fun stripImportantFromCss_consumesLeadingWhitespace() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000    !important"))
    }

    @Test
    fun stripImportantFromCss_removesCommentSplitImportant() {
        assertEquals("color:#000000", stripImportantFromCss("color:#000000!/**/important"))
        assertEquals("color:#000000", stripImportantFromCss("color:#000000 !/*x*/important"))
    }

    @Test
    fun stripImportantFromCss_removesEscapeSplitImportant() {
        // \49 is the CSS escape for code point 0x49 ("I"), so this decodes to "!Important".
        assertEquals("color:#000000", stripImportantFromCss("""color:#000000!\49 mportant"""))
    }

    @Test
    fun stripImportantFromCss_survivesEscapesAboveTheUnicodeCodespace() {
        // CSS_ESCAPE accepts six hex digits (up to 0xFFFFFF) while Character.toChars THROWS above
        // 0x10FFFF. The sender picks this value, and it used to reach EmailDetailActivity's
        // ioExecutor as an uncaught IllegalArgumentException — a process kill that repeated on
        // every reopen, because the message stays in the mailbox.
        for (hex in listOf("110000", "ffffff", "FFFFFF", "7FFFFF")) {
            val input = """color:red !\$hex mportant"""
            assertEquals(input, stripImportantFromCss(input))
        }
    }

    @Test
    fun stripImportantFromCss_stillDecodesTheHighestValidCodePoint() {
        // 0x10FFFF is the last valid code point — the boundary the guard must not over-reject.
        val input = """color:red !\10FFFF mportant"""
        assertEquals(input, stripImportantFromCss(input))
    }

    // ---- stripImportant: which parts of the document the removal reaches ----

    @Test
    fun stripImportant_removesEveryOccurrenceInStyleAttributesAndStyleBlocks() {
        val input = """<div style="color:#000 !important; background:#fff !important"><style>.x{color:red!important}</style></div>"""
        assertFalse(stripImportant(input).contains("important", ignoreCase = true))
    }

    @Test
    fun stripImportant_leavesEverythingElseUnchanged() {
        val input = """<div style="color:#000000">plain text, no important here</div>"""
        assertEquals(input, stripImportant(input))
    }

    /**
     * The old version was a text sweep over the whole body, so it rewrote prose. `!important` in
     * visible text is not a CSS declaration and removing it changes what the message says.
     */
    @Test
    fun stripImportant_doesNotRewriteBodyText() {
        val input = "<p>Great job! Hope you're well. This is !important to me.</p>"
        assertEquals(input, stripImportant(input))
    }

    /**
     * Parsing means the token patterns only ever see one attribute or one `<style>` block, so the
     * inputs that made the whole-body regex quadratic — an unclosed comment, a body of nothing but
     * whitespace — are no longer reachable, and the 512KB "skip it entirely" cap is gone with them.
     * Measured before: ~23s at 128KB, ~4 minutes at 512KB, from a body containing no `!` at all.
     */
    @Test
    fun stripImportant_terminatesQuicklyOnHostileBodies() {
        val hostile = listOf(
            "/*" + "a".repeat(200_000),
            " ".repeat(200_000),
            " ".repeat(200_000) + "!",
            "<p>" + "x".repeat(600_000) + "</p>",
        )
        hostile.forEach { body ->
            val elapsed = kotlin.system.measureTimeMillis { stripImportant(body) }
            assertTrue("stripImportant took ${elapsed}ms", elapsed < 2_000)
        }
    }

    /** No size cap any more: a large body is still cleaned, because the parse bounds the work
     *  instead of the length check doing it. */
    @Test
    fun stripImportant_stillCleansLargeBodies() {
        val huge = """<div style="color:#000 !important">""" + "x".repeat(600_000) + "</div>"
        assertFalse(stripImportant(huge).contains("important", ignoreCase = true))
    }

    // ---- attachment name and type sanitising ----

    @Test
    fun safeFileName_stripsPathsAndControlCharacters() {
        assertEquals("invoice.pdf", safeFileName("../../etc/invoice.pdf"))
        assertEquals("invoice.pdf", safeFileName("""C:\windows\invoice.pdf"""))
        assertEquals("invoice.pdf.apk", safeFileName("invoice.pdf\u0000.apk"))
        assertEquals("attachment", safeFileName(""))
        assertEquals("attachment", safeFileName("///"))
        assertEquals("hidden", safeFileName(".hidden"))
        assertEquals(120, safeFileName("a".repeat(500)).length)
    }

    @Test
    fun safeMimeType_downgradesAnythingNotOnTheAllowlist() {
        assertEquals("application/pdf", safeMimeType("application/pdf"))
        assertEquals("application/pdf", safeMimeType("Application/PDF; charset=utf-8"))
        // A type only the sender's own app claims would otherwise make it the sole resolver.
        assertEquals("application/octet-stream", safeMimeType("application/vnd.attacker-x"))
        assertEquals("application/octet-stream", safeMimeType(""))
    }

    // isDarkPalette() itself (the bg-luminance → dark/light classification) calls
    // android.graphics.Color.parseColor, which isn't available in a plain JVM unit test (no
    // Robolectric in this module — see every other test file's Android-framework-free style) —
    // covered instead by buildEmailBodyHtml's own isDark parameter above, and by manual/instrumented
    // verification that a dark theme's palette.bg does trigger the override branch in the real app.

    // ---- showsRetryButton: which ReadOutcome offers a Retry tap ----

    /** Every non-FetchFailed row of the exit table, once each. The two easiest to confuse with a
     *  transport failure are the actual target: [ReadOutcome.NoEncryptedContent] is terminal (the
     *  server answered "no payload"; retrying cannot change that) and [ReadOutcome.DecryptFailed]
     *  is a local decrypt failure, not a fetch failure — neither should offer Retry. */
    private val nonRetryableOutcomes = listOf(
        ReadOutcome.Decrypted(
            body = DecryptedBody(html = "<p>hi</p>", plain = null, protectedSubject = null),
            signature = PgpSignatureState.NONE,
            resolvedSender = "bob@example.com",
        ),
        ReadOutcome.NeedsUnlock,
        ReadOutcome.Cancelled,
        ReadOutcome.NotEnrolled,
        ReadOutcome.NoSecureLockScreen,
        ReadOutcome.TooLarge,
        ReadOutcome.NotClientProtected,
        ReadOutcome.UnsealFailed("could not open"),
        ReadOutcome.NoEncryptedContent,
        ReadOutcome.DecryptFailed("bad padding"),
    )

    @Test
    fun showsRetryButton_isTrueOnlyForFetchFailed() {
        assertTrue(showsRetryButton(ReadOutcome.FetchFailed("network error")))
    }

    @Test
    fun showsRetryButton_isFalseForEveryOtherExitTableRow() {
        nonRetryableOutcomes.forEach { outcome ->
            assertFalse("expected no Retry for $outcome", showsRetryButton(outcome))
        }
    }

    /** [ReadOutcome.NoEncryptedContent] specifically: the server answered, so a Retry button here
     *  would invite the user to tap it forever. Deliberate-break check inline, not just a shared
     *  loop assertion, since this is the one row the brief calls out by name as never-Retry. */
    @Test
    fun showsRetryButton_isFalseForNoEncryptedContent() {
        assertFalse(showsRetryButton(ReadOutcome.NoEncryptedContent))
    }

    // ---- displaySignatureVerdict: the verdict actually safe to display ----

    private val decryptedBody = DecryptedBody(html = "<p>hi</p>", plain = null, protectedSubject = null)

    @Test
    fun displaySignatureVerdict_passesThroughASignatureWithAResolvedSender() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.VERIFIED_CONFIRMED,
            resolvedSender = "bob@example.com",
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, displaySignatureVerdict(outcome))
    }

    /**
     * The security case this function exists for: PgpPayloadResult.resolvedSender's own KDoc says
     * it is empty "e.g. [for] a multi-mailbox From" — exactly the attacker-separable shape ("Bob
     * Smith (Eve <eve@evil.example>) <bob@example.com>" and its relatives) the resolved-vs-raw
     * sender display rule exists for. A non-NONE signature with no resolved mailbox to pin it to
     * must not reach the screen, where it would read as being about whatever raw sender text is
     * still displayed.
     */
    @Test
    fun displaySignatureVerdict_suppressesASignatureWithNoResolvedSender() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.SIGNER_UNKNOWN,
            resolvedSender = "",
        )
        assertEquals(PgpSignatureState.NONE, displaySignatureVerdict(outcome))
    }

    @Test
    fun displaySignatureVerdict_isNoneWhenTheReadOutcomeItselfIsNone() {
        val outcome = ReadOutcome.Decrypted(
            body = decryptedBody,
            signature = PgpSignatureState.NONE,
            resolvedSender = "bob@example.com",
        )
        assertEquals(PgpSignatureState.NONE, displaySignatureVerdict(outcome))
    }

    // ---- mayReplyOrForward: which PgpMessageState blocks Reply/Reply-All/Forward ----

    /** The one state Task 11 exists for: no safe destination for a quoted decrypted body, so this
     *  must be false even once the message has been decrypted on screen — see
     *  EmailDetailActivity.applyReplyForwardAvailability's KDoc for why that has to hold
     *  unconditionally rather than just before decrypt succeeds. */
    @Test
    fun mayReplyOrForward_isFalseForClientProtected() {
        assertFalse(mayReplyOrForward(PgpMessageState.CLIENT_PROTECTED))
    }

    /** Every other state must stay true, so a change that widens the block (e.g. mistakenly
     *  gating on DECRYPT_FAILED too) fails a test rather than shipping silently disabled buttons
     *  on messages with a perfectly good server-side body. Enumerated via [PgpMessageState.entries]
     *  rather than hand-listed, so a future state added to the enum is covered automatically
     *  instead of silently passing unchecked. */
    @Test
    fun mayReplyOrForward_isTrueForEveryOtherState() {
        PgpMessageState.entries.filter { it != PgpMessageState.CLIENT_PROTECTED }.forEach { state ->
            assertTrue("expected $state to allow reply/forward", mayReplyOrForward(state))
        }
    }

    // ---- initialReplyForwardState: the fail-closed default before renderBody's fetch answers ----

    /** The case this function exists for: `renderBody`'s background fetch may take a network
     *  round trip, or never complete at all if it throws, so an encrypted message must default to
     *  blocked — not to allowed-until-proven-otherwise — or Reply is live for that whole window on
     *  exactly the messages this task exists to protect. */
    @Test
    fun initialReplyForwardState_failsClosedWhenEncrypted() {
        val state = initialReplyForwardState(pgpEncrypted = true)
        assertEquals(PgpMessageState.CLIENT_PROTECTED, state)
        assertFalse(mayReplyOrForward(state))
    }

    /** An unencrypted message was never going to become CLIENT_PROTECTED, so it isn't held
     *  hostage to the same wait. */
    @Test
    fun initialReplyForwardState_isNoneWhenNotEncrypted() {
        assertEquals(PgpMessageState.NONE, initialReplyForwardState(pgpEncrypted = false))
    }
}
