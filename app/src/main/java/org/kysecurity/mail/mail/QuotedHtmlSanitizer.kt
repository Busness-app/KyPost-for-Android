package org.kysecurity.mail.mail

import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

/**
 * Strips executable and resource-loading constructs out of a sender's message before it is quoted
 * into the compose editor.
 *
 * The reader ([org.kysecurity.mail.EmailDetailActivity]) renders sender HTML with JavaScript off,
 * network loads blocked and an opaque origin, so it is safe there. The **composer** is a different
 * WebView: `android-rich-html-editor` sets `setJavaScriptEnabled(true)` and
 * `addJavascriptInterface(jsBridge, "editor")`, and its `setHtml` assigns straight to `innerHTML`.
 * The library's own escaper handles a backtick, a backslash and a dollar sign — it is a JavaScript
 * string-literal escaper, not an HTML sanitizer, and does not claim to be.
 *
 * A `<script>` inserted via `innerHTML` does not execute, but **event handler content attributes on
 * inserted elements do**. Quoting a sender's `<img src=x onerror=...>` into a reply therefore gave
 * them script execution in the document holding the user's outgoing message, with the `editor`
 * bridge in reach.
 *
 * Allowlist-based and parser-backed rather than pattern-based: a regex over markup loses to mXSS and
 * to malformed tags the browser re-interprets. K-9 and FairEmail resolve this the same way.
 */
object QuotedHtmlSanitizer {

    /**
     * [Safelist.relaxed] preserves formatting — headings, lists, tables, links — so a quoted reply
     * still looks like the message it quotes. Everything unnamed is dropped, which covers
     * `<script>`, `<iframe>`, `<object>`, `<embed>`, `<svg>` and every `on*` attribute, since
     * attributes are allowlisted per tag rather than denylisted. It also enforces a protocol
     * allowlist on `href`/`src` (removing `javascript:` and `data:`) and does not permit `style`.
     */
    private val safelist: Safelist = Safelist.relaxed()
        // `relaxed()` permits <img src="http://…">, and the composer WebView has network access.
        // Quoting therefore fired the sender's tracking beacon while the reply was being written —
        // the exact leak the reader blocks with blockNetworkLoads and its opt-in "Show images" bar.
        .removeTags("img")

    fun sanitize(html: String): String {
        if (html.isBlank()) return ""
        // Empty base URI: relative links in the quote stay relative rather than being resolved
        // against a host we would have to invent.
        return runCatching { Jsoup.clean(html, "", safelist) }
            // A quote we cannot parse is not a quote we may pass through. Failing to the escaped
            // source text keeps the user's context while guaranteeing nothing executes.
            .getOrElse { org.jsoup.parser.Parser.unescapeEntities(html, false).let(::escapeAsText) }
    }

    private fun escapeAsText(text: String): String =
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
}
