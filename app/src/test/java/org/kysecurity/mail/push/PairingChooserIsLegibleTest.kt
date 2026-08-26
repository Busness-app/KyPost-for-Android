package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Two installed channels both claim `kypost://native-pair`, so Android shows a chooser — on the
 *  pairing deep link, which is the first thing a new user touches.
 *
 *  Per-flavor `applicationId`s cannot fix that, and per-flavor URI schemes are ruled out: the
 *  server builds the pairing link as a literal `kypost://native-pair?...`, the phishing scanner
 *  matches that exact string to catch a takeover link in received mail, and the HTML sanitizer
 *  allowlists it by name. A flavor listening on `kypost-fdroid://` would not match the QR the
 *  server emits, and — worse — would not be caught by the scanner.
 *
 *  So the chooser stays and is made legible instead: each channel carries its own app name, and
 *  the chooser shows it. That works today only because of two facts that nothing else asserts,
 *  and both are one edit away from silently reverting to three identical "KyPost" rows:
 *
 *   1. the exported forwarder declares no `android:label`, so it inherits the application's; and
 *   2. each flavor's `app_name` is distinct.
 *
 *  Neither would fail a build. Hence this test. */
class PairingChooserIsLegibleTest {

    private fun repoFile(path: String): File =
        listOf(File(path), File("app/$path")).firstOrNull { it.exists() }
            ?: error("Could not locate $path from ${File(".").absolutePath}")

    private fun appName(stringsPath: String): String? {
        val text = repoFile(stringsPath).readText()
        return APP_NAME.find(text)?.groupValues?.get(1)
    }

    /** `ResolveInfo.loadLabel()` prefers the ACTIVITY's label and only falls back to the
     *  application's. A label here — even a well-meaning "Pair device" — would be identical
     *  across all three channels and put the chooser back where it started. */
    @Test
    fun theExportedPairingForwarderDeclaresNoLabelOfItsOwn() {
        val manifest = repoFile("src/main/AndroidManifest.xml").readText()
        val activity = ACTIVITY_BLOCK.find(manifest)?.value
        requireNotNull(activity) { "PushPairingLinkActivity is not declared in src/main/AndroidManifest.xml" }

        assertNull(
            "PushPairingLinkActivity declares android:label, so the kypost:// chooser shows the " +
                "same text for every channel. Remove it and let the per-flavor app_name through.",
            LABEL.find(activity)?.value,
        )
    }

    /** The application label is what the forwarder inherits, so it has to be a resource that a
     *  flavor can override rather than a literal. */
    @Test
    fun theApplicationLabelIsTheOverridableResource() {
        val manifest = repoFile("src/main/AndroidManifest.xml").readText()

        assertTrue(
            "<application> must carry android:label=\"@string/app_name\" — that is the string " +
                "each flavor overrides to make the chooser legible.",
            manifest.contains("""android:label="@string/app_name""""),
        )
    }

    /** play deliberately has no override and keeps the plain name; the other two must differ from
     *  it and from each other, or the chooser names two channels the same thing. */
    @Test
    fun everyChannelHasItsOwnNameInTheChooser() {
        val play = appName("src/main/res/values/strings.xml")
        val github = appName("src/github/res/values/strings.xml")
        val fdroid = appName("src/fdroid/res/values/strings.xml")

        val names = listOf("play" to play, "github" to github, "fdroid" to fdroid)
        names.forEach { (flavor, name) ->
            requireNotNull(name) { "$flavor has no app_name; the chooser would fall back to another channel's." }
        }

        assertEquals(
            "Two channels share a chooser label: $names",
            3,
            names.mapNotNull { it.second }.toSet().size,
        )
    }

    private companion object {
        val APP_NAME = Regex("""<string name="app_name">([^<]*)</string>""")
        val ACTIVITY_BLOCK = Regex("""<activity[^>]*PushPairingLinkActivity.*?</activity>""", RegexOption.DOT_MATCHES_ALL)
        val LABEL = Regex("""android:label\s*=""")
    }
}
