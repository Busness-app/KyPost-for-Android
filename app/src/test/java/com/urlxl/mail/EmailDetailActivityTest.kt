package com.urlxl.mail

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

    // ---- stripImportant ----

    @Test
    fun stripImportant_removesLowercaseImportant() {
        assertEquals("color:#000000", stripImportant("color:#000000 !important"))
    }

    @Test
    fun stripImportant_isCaseInsensitive() {
        assertEquals("color:#000000", stripImportant("color:#000000 !IMPORTANT"))
    }

    @Test
    fun stripImportant_toleratesNoSpaceBeforeImportant() {
        assertEquals("color:#000000", stripImportant("color:#000000!important"))
    }

    @Test
    fun stripImportant_removesEveryOccurrence() {
        val input = """<div style="color:#000 !important; background:#fff !important"><style>.x{color:red!important}</style></div>"""
        assertFalse(stripImportant(input).contains("important", ignoreCase = true))
    }

    @Test
    fun stripImportant_leavesEverythingElseUnchanged() {
        val input = """<div style="color:#000000">plain text, no important here</div>"""
        assertEquals(input, stripImportant(input))
    }

    @Test
    fun stripImportant_removesCssCommentSplitImportant() {
        assertEquals("color:#000000", stripImportant("color:#000000!/**/important"))
    }

    @Test
    fun stripImportant_removesEscapeSplitImportant() {
        // \49 is the CSS escape for code point 0x49 ("I"), so this decodes to "!Important".
        assertEquals("color:#000000", stripImportant("""color:#000000!\49 mportant"""))
    }

    @Test
    fun stripImportant_survivesEscapesAboveTheUnicodeCodespace() {
        // The sender picks this. CSS_ESCAPE accepts six hex digits (up to 0xFFFFFF) while
        // Character.toChars THROWS above 0x10FFFF, so this used to raise IllegalArgumentException
        // out of stripImportant — on EmailDetailActivity's ioExecutor, where an uncaught exception
        // kills the process. The message stays in the mailbox, so every reopen crashed again.
        for (hex in listOf("110000", "ffffff", "FFFFFF", "7FFFFF")) {
            val input = """<p style="color:red !\$hex mportant">hi</p>"""
            assertEquals(input, stripImportant(input))
        }
    }

    @Test
    fun stripImportant_stillDecodesTheHighestValidCodePoint() {
        // 0x10FFFF is the last valid code point — the boundary the guard must not over-reject.
        // It is not a letter of "important", so the candidate is left alone rather than stripped;
        // what matters is that it decodes instead of throwing.
        val input = """color:red !\10FFFF mportant"""
        assertEquals(input, stripImportant(input))
    }

    @Test
    fun stripImportant_doesNotAlterUnrelatedBangText() {
        val input = "Great job! Hope you're well."
        assertEquals(input, stripImportant(input))
    }

    @Test
    fun stripImportant_removesCommentSplitImportant() {
        assertEquals("color:#000000", stripImportant("color:#000000 !/*x*/important"))
    }

    @Test
    fun stripImportant_terminatesQuicklyOnAnUnclosedComment() {
        // The sender picks this input. With the old lazy `/\*.*?\*/` + DOT_MATCHES_ALL pattern an
        // unterminated comment made the scan quadratic over the whole body; assert it stays fast
        // rather than merely correct.
        val hostile = "/*" + "a".repeat(200_000)
        val elapsed = kotlin.system.measureTimeMillis { stripImportant(hostile) }
        assertTrue("stripImportant took ${elapsed}ms on an unclosed comment", elapsed < 2_000)
    }

    /**
     * The unclosed-comment case above passes in ~30ms even on the pre-fix pattern, so it never
     * exercised the `!`-candidate backtracking it appeared to guard. Whitespace is the input that
     * actually blew up: an unbounded leading `\s*` gave the pattern no literal first character, so
     * the engine consumed to end-of-input from every offset. Measured before the fix: ~23s at 128KB
     * and ~4 minutes at the 512KB cap, from a body containing no `!` at all.
     */
    @Test
    fun stripImportant_terminatesQuicklyOnWhitespaceHeavyBody() {
        val hostile = " ".repeat(200_000)
        val elapsed = kotlin.system.measureTimeMillis { stripImportant(hostile) }
        assertTrue("stripImportant took ${elapsed}ms on an all-whitespace body", elapsed < 2_000)
    }

    /** Same shape, but with a trailing `!` so the candidate branch is entered rather than skipped. */
    @Test
    fun stripImportant_terminatesQuicklyOnWhitespaceFollowedByBang() {
        val hostile = " ".repeat(200_000) + "!"
        val elapsed = kotlin.system.measureTimeMillis { stripImportant(hostile) }
        assertTrue("stripImportant took ${elapsed}ms on whitespace + bang", elapsed < 2_000)
    }

    /** The bounded whitespace run must still consume the space before `!important`, which is what
     *  keeps the surrounding declaration clean. */
    @Test
    fun stripImportant_stillConsumesLeadingWhitespace() {
        assertEquals("color:#000000", stripImportant("color:#000000 !important"))
        assertEquals("color:#000000", stripImportant("color:#000000    !important"))
    }

    @Test
    fun stripImportant_skipsBodiesOverTheSizeCap() {
        // Past the cap it is a no-op rather than an unbounded regex pass: this is a dark-mode
        // rendering nicety, not a security control.
        val huge = "color:#000 !important".padEnd(600_000, 'x')
        assertEquals(huge, stripImportant(huge))
    }

    // isDarkPalette() itself (the bg-luminance → dark/light classification) calls
    // android.graphics.Color.parseColor, which isn't available in a plain JVM unit test (no
    // Robolectric in this module — see every other test file's Android-framework-free style) —
    // covered instead by buildEmailBodyHtml's own isDark parameter above, and by manual/instrumented
    // verification that a dark theme's palette.bg does trigger the override branch in the real app.
}
