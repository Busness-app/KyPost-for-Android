package com.urlxl.mail.mail

import org.junit.Assert.assertTrue
import org.junit.Test

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
class Run4SanitizerMxssProbeTest {

    private val payloads = listOf(
        // foreign-content / parse-mode switches
        "<svg><style><!--</style><img src=x onerror=alert(1)>-->",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<svg></p><style><a id=\"</style><img src=x onerror=alert(1)>\">",
        "<math><mtext><i>a</i><style><!--</style><img src=x onerror=alert(1)>",
        "<svg><p><style><a id=\"</style><img src=x onerror=alert(1)>\">",
        // noscript: parsed as elements by jsoup, as raw text by a scripting-enabled browser
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<noscript>&lt;img src=x onerror=alert(1)&gt;</noscript>",
        "<noscript><style></noscript><img src=x onerror=alert(1)>",
        // template
        "<template><img src=x onerror=alert(1)></template>",
        "<template><p title=\"</template><img src=x onerror=alert(1)>\">",
        // raw-text elements the allowlist drops
        "<xmp><img src=x onerror=alert(1)></xmp>",
        "<listing><img src=x onerror=alert(1)></listing>",
        "<plaintext><img src=x onerror=alert(1)>",
        "<textarea><img src=x onerror=alert(1)></textarea>",
        "<title><img src=x onerror=alert(1)></title>",
        "<iframe><img src=x onerror=alert(1)></iframe>",
        "<style><img src=x onerror=alert(1)></style>",
        "<script><img src=x onerror=alert(1)></script>",
        // comments and CDATA
        "<!--><img src=x onerror=alert(1)>-->",
        "<!--[if]><img src=x onerror=alert(1)><![endif]-->",
        "<![CDATA[<img src=x onerror=alert(1)>]]>",
        "<?xml-stylesheet><img src=x onerror=alert(1)>",
        // attribute-value breakout attempts
        "<a title=\"&quot; onmouseover=alert(1) x=&quot;\">t</a>",
        "<a title='\" onmouseover=alert(1) x=\"'>t</a>",
        "<img alt=\"&lt;/img&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">",
        "<a href=\"https://x\" title=\"</a><img src=x onerror=alert(1)>\">t</a>",
        "<a title=\" \" onmouseover=alert(1)>t</a>",
        // entity / encoding tricks
        "<a href=\"&#106;avascript:alert(1)\">t</a>",
        "<a href=\"jav&#x0A;ascript:alert(1)\">t</a>",
        "<a href=\"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)\">t</a>",
        "<a href=\"java\tscript:alert(1)\">t</a>",
        "<a href=\"javascript:alert(1)\">t</a>",
        // mutation via unbalanced/uppercase/namespaced markup
        "<SVG/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<img src=x onerror=alert(1)//",
        "<a xlink:href=\"javascript:alert(1)\">t</a>",
        "<div><svg><desc><div></desc><img src=x onerror=alert(1)>",
        // the sanitizer's own fallback branch: unescape-then-escape
        "&lt;img src=x onerror=alert(1)&gt;",
        "&amp;lt;img src=x onerror=alert(1)&amp;gt;",
    )

    private val forbiddenTags = setOf(
        "script", "iframe", "object", "embed", "svg", "math", "form", "input",
        "style", "link", "meta", "base", "noscript", "template", "xmp", "plaintext", "textarea",
    )

    /**
     * Re-parses the sanitized output the way a browser would and reports anything executable.
     *
     * Structural, not a regex over the serialized string. A regex cannot tell `onerror=` inside a
     * quoted `title` attribute (inert) or inside escaped text (inert) from a real event-handler
     * attribute, and both shapes occur throughout this battery — so a string-level detector reports
     * false positives on exactly the payloads it exists to judge.
     */
    private fun executableConstructsIn(sanitized: String): List<String> {
        val doc = org.jsoup.Jsoup.parseBodyFragment(sanitized)
        val problems = mutableListOf<String>()
        doc.body().select("*").forEach { el ->
            if (el.tagName().lowercase() in forbiddenTags) problems += "<${el.tagName()}>"
            el.attributes().forEach { attr ->
                val name = attr.key.lowercase()
                if (name.startsWith("on")) problems += "${el.tagName()}[$name]"
                if (name == "href" || name == "src" || name == "xlink:href") {
                    val scheme = attr.value.trim()
                        .replace(Regex("[\\u0000-\\u0020]"), "")
                        .substringBefore(':', missingDelimiterValue = "")
                        .lowercase()
                    if (scheme == "javascript" || scheme == "data" || scheme == "vbscript") {
                        problems += "${el.tagName()}[$name=$scheme:]"
                    }
                }
            }
        }
        return problems
    }

    @Test
    fun noPayloadSurvivesAsExecutableMarkup() {
        val survivors = payloads.mapNotNull { p ->
            val problems = executableConstructsIn(QuotedHtmlSanitizer.sanitize(p))
            if (problems.isEmpty()) null else "$p -> $problems"
        }
        assertTrue("executable markup survived sanitization: $survivors", survivors.isEmpty())
    }

    @Test
    fun everyOutputIsStableUnderReSanitization() {
        val unstable = payloads.filter { p ->
            val once = QuotedHtmlSanitizer.sanitize(p)
            once != QuotedHtmlSanitizer.sanitize(once)
        }
        assertTrue("sanitizer output is not a fixed point (mXSS signature): $unstable", unstable.isEmpty())
    }

    /**
     * Already-escaped markup must survive as escaped markup, not be unwrapped into live tags.
     *
     * This shape also exercises the catch-all fallback in [QuotedHtmlSanitizer], which unescapes
     * entities and re-escapes them; getting the order wrong there would turn quoted text back into
     * parsed elements on the way into a JavaScript-enabled WebView.
     */
    @Test
    fun escapedMarkupStaysEscaped() {
        listOf(
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;",
        ).forEach { input ->
            val out = QuotedHtmlSanitizer.sanitize(input)
            assertTrue(
                "escaped markup must not be unwrapped into live tags: $input -> $out",
                executableConstructsIn(out).isEmpty(),
            )
        }
    }
}
