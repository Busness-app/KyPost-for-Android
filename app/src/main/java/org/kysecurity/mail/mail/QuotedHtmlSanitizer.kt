package org.kysecurity.mail.mail

import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

/**
 * Strips executable and resource-loading constructs out of a sender's message before it is quoted
 * into the compose editor.
 *
 * The reader ([org.kysecurity.mail.EmailDetailActivity]) renders sender HTML with `javaScriptEnabled =
 * false`, `blockNetworkLoads = true` and an opaque origin, so it is safe there. The **composer** is
 * a different WebView: `android-rich-html-editor` builds it with `setJavaScriptEnabled(true)` and
 * `addJavascriptInterface(jsBridge, "editor")`, and its `setHtml` assigns the string straight to
 * `document.getElementById("editor").innerHTML` via `evaluateJavascript`. The library's own
 * escaper only escapes a backtick, a backslash and a dollar sign — it is a JavaScript *string
 * literal* escaper, not an HTML sanitizer, and it is not trying to be one; the method is called
 * `insertUserHtml` because it assumes the caller authored the markup.
 *
 * Per the HTML spec a `<script>` inserted via `innerHTML` does not execute, but **event handler
 * content attributes on inserted elements do**. So quoting a sender's `<img src=x onerror=...>`
 * into a reply gave that sender script execution inside the document holding the user's outgoing
 * message, with the `editor` bridge in reach — enough to read the reply as it is typed and to
 * resolve the pending Send callback with attacker-authored HTML.
 *
 * Allowlist-based and parser-backed rather than pattern-based on purpose: a regex over markup loses
 * to mXSS and to malformed tags that the browser re-interprets, and every mainstream client that
 * quotes untrusted HTML into a composer (K-9, FairEmail) resolves this the same way.
 */
object QuotedHtmlSanitizer {

    /**
     * [Safelist.relaxed] is the formatting-preserving allowlist: headings, lists, tables, links and
     * images survive, so a quoted reply still looks like the message it quotes. Everything not
     * named is dropped — which covers `<script>`, `<iframe>`, `<object>`, `<embed>`, `<svg>` and
     * every `on*` attribute, because attributes are allowlisted per tag rather than denylisted.
     * It also enforces a protocol allowlist on `href` and `src`, which is what removes
     * `javascript:` and `data:` URLs, and it does not permit `style`, so CSS-based tricks go too.
     */
    private val safelist: Safelist = Safelist.relaxed()

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
