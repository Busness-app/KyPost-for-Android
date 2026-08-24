package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Guards the list of jakarta.mail content handlers that `proguard-rules.pro` keeps and
 * `checkRuntimeMatchedClassNames` enforces.
 *
 * These classes are named as STRINGS in `META-INF/mailcap` and loaded by `MailcapCommandMap`, so
 * no bytecode refers to them and R8 removes them unless a keep rule says otherwise. When it did,
 * jakarta.activation fell back to `DataSourceDataContentHandler`, whose `getContent()` answers an
 * InputStream rather than a String or a MimeMultipart — so [PgpMimeReader] found no body at all and
 * every decrypted message in a release build ended as "could not be read once decrypted".
 *
 * No unit test can observe that: this suite runs unminified, with every handler on the classpath.
 * What it CAN do is stop the kept list from silently falling behind what mailcap declares, which is
 * how a jakarta.mail upgrade would reintroduce the bug. The build gate proves R8 honoured the list;
 * this proves the list is still the right one.
 */
class MimeContentHandlersTest {

    /** Must stay level with `runtimeMatchedClassNames` in `app/build.gradle.kts` and the
     *  `-keep class org.eclipse.angus.mail.handlers.*` rules in `proguard-rules.pro`. */
    private val kept = setOf(
        "org.eclipse.angus.mail.handlers.text_plain",
        "org.eclipse.angus.mail.handlers.text_html",
        "org.eclipse.angus.mail.handlers.text_xml",
        "org.eclipse.angus.mail.handlers.multipart_mixed",
        "org.eclipse.angus.mail.handlers.message_rfc822",
    )

    @Test
    fun everyHandlerMailcapDeclaresIsOneWeKeep() {
        assertEquals(
            "META-INF/mailcap declares a different set of content handlers than the release build " +
                "keeps. Update runtimeMatchedClassNames in app/build.gradle.kts, the -keep rules " +
                "in proguard-rules.pro, and this list — all three, or release loses a body type.",
            kept,
            declaredHandlers(),
        )
    }

    /** The names are only useful if they still resolve; an upgrade that relocates one would leave
     *  a keep rule matching nothing, which reads exactly like a keep rule that works. */
    @Test
    fun everyKeptHandlerNameStillResolves() {
        for (name in kept) Class.forName(name)
    }

    private fun declaredHandlers(): Set<String> =
        javaClass.classLoader!!.getResources("META-INF/mailcap").asSequence()
            .flatMap { it.readText().lineSequence() }
            .map { it.substringBefore('#').trim() }
            .filter { it.contains("x-java-content-handler=") }
            .map { it.substringAfter("x-java-content-handler=").substringBefore(';').trim() }
            .toSet()

    private fun java.net.URL.readText(): String = openStream().use { it.readBytes().toString(Charsets.UTF_8) }
}
