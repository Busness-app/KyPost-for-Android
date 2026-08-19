package org.kysecurity.mail

import org.kysecurity.mail.pgp.DecryptedBody
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.ReadOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
        // CSS_ESCAPE accepts six hex digits (0xFFFFFF); Character.toChars throws above 0x10FFFF.
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

    @Test
    fun stripImportant_doesNotRewriteBodyText() {
        val input = "<p>Great job! Hope you're well. This is !important to me.</p>"
        assertEquals(input, stripImportant(input))
    }

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

    @Test
    fun stripImportant_stillCleansLargeBodies() {
        val huge = """<div style="color:#000 !important">""" + "x".repeat(600_000) + "</div>"
        assertFalse(stripImportant(huge).contains("important", ignoreCase = true))
    }

    @Test
    fun safeFileName_stripsPathsAndControlCharacters() {
        assertEquals("invoice", safeFileName("../../etc/invoice.pdf"))
        assertEquals("invoice", safeFileName("""C:\windows\invoice.pdf"""))
        assertEquals("attachment", safeFileName(""))
        assertEquals("attachment", safeFileName("///"))
        assertEquals("hidden", safeFileName(".hidden"))
        assertEquals(120, safeFileName("a".repeat(500)).length)
    }

    @Test
    fun safeFileName_takesItsExtensionFromTheDeclaredTypeNotTheSenderName() {
        assertEquals("invoice.pdf", safeFileName("invoice.pdf", "application/pdf"))
        assertEquals("invoice.pdf", safeFileName("invoice.exe", "application/pdf"))
        assertEquals("invoice", safeFileName("invoice.pdf\u0000.apk", "application/octet-stream"))
        assertEquals("photo.jpg", safeFileName("photo.jpeg", "image/jpeg"))
        assertEquals("payload", safeFileName("payload.apk", "application/vnd.android.package-archive"))
        // Ordinary dotted names keep their text: only short alphanumeric trailing segments count
        // as extensions.
        assertEquals("minutes.2026 Q1 final", safeFileName("minutes.2026 Q1 final", ""))
    }

    @Test
    fun safeMimeType_downgradesAnythingNotOnTheAllowlist() {
        assertEquals("application/pdf", safeMimeType("application/pdf"))
        assertEquals("application/pdf", safeMimeType("Application/PDF; charset=utf-8"))
        // A type only the sender's own app claims would otherwise make it the sole resolver.
        assertEquals("application/octet-stream", safeMimeType("application/vnd.attacker-x"))
        assertEquals("application/octet-stream", safeMimeType(""))
    }

    // isDarkPalette() needs android.graphics.Color, so it is not covered here; isDark is passed in.

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

    @Test
    fun showsRetryButton_isFalseForNoEncryptedContent() {
        assertFalse(showsRetryButton(ReadOutcome.NoEncryptedContent))
    }

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

    @Test
    fun mayReplyOrForward_isFalseForClientProtected() {
        assertFalse(mayReplyOrForward(PgpMessageState.CLIENT_PROTECTED))
    }

    @Test
    fun mayReplyOrForward_isTrueForEveryOtherState() {
        PgpMessageState.entries.filter { it != PgpMessageState.CLIENT_PROTECTED }.forEach { state ->
            assertTrue("expected $state to allow reply/forward", mayReplyOrForward(state))
        }
    }

    @Test
    fun initialReplyForwardState_failsClosedWhenEncrypted() {
        val state = initialReplyForwardState(pgpEncrypted = true)
        assertEquals(PgpMessageState.CLIENT_PROTECTED, state)
        assertFalse(mayReplyOrForward(state))
    }

    @Test
    fun initialReplyForwardState_isNoneWhenNotEncrypted() {
        assertEquals(PgpMessageState.NONE, initialReplyForwardState(pgpEncrypted = false))
    }
}
