package org.kysecurity.mail.mail

import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

// The composer WebView has JS on and an `editor` bridge, so quoted sender HTML must be sanitized.
object QuotedHtmlSanitizer {

    private val safelist: Safelist = Safelist.relaxed()
        // `relaxed()` permits <img>, and the composer has network access: a tracking beacon.
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
