package org.kysecurity.mail

import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Two project rules that were previously stated in KDoc and enforced by nothing, asserted against
 * the source tree itself.
 *
 * Both had already been violated by the time they were written down — three files carried the very
 * `ByteArray`-in-a-`data class` shape that three other files each spend a paragraph forbidding —
 * which is the argument for this file existing. A rule a human has to remember is not a rule.
 *
 * Reads the tree as text rather than through reflection or a linter dependency: it needs no new
 * artifact in `gradle/verification-metadata.xml`, and it is unaffected by
 * `isReturnDefaultValues = true` because it touches no `android.*` API.
 */
class SourceRulesTest {

    /**
     * `data class` + a [ByteArray] property means Kotlin generates identity `equals`/`hashCode`
     * while the type advertises structural equality — a silent trap on exactly the types that hold
     * key material, ciphertext and plaintext.
     *
     * A class that writes both overrides itself has made the decision deliberately and is allowed;
     * see `PgpDecryptor.DecryptResult.Ok`.
     */
    @Test
    fun noDataClassCarriesAByteArrayWithoutOverridingEquality() {
        val offenders = mainSources().flatMap { file ->
            dataClassesIn(file.readText())
                .filter { PARAM_IS_BYTE_ARRAY.containsMatchIn(it.parameters) }
                .filterNot { it.declaresOwnEquality() }
                .map { "${file.path}: data class ${it.name}" }
        }
        assertEquals(
            emptyList(), offenders,
            "Use a plain class (or override equals/hashCode). See WrappedSecret and PinHash.",
        )
    }

    /**
     * `isReturnDefaultValues = true` makes every stubbed `android.*` call return a default instead
     * of working. Most stubs are harmless in a JVM test — nothing exercises a `TextView`. These two
     * are not: `android.util.Base64` returns null and `org.json` returns nothing, *silently*, so a
     * suite over code that uses them passes without testing anything. `DeviceEnvelope`'s KDoc
     * records a suite that stayed green against a `= null` body for exactly this reason.
     *
     * Scoped to production files that have a same-named JVM test, which is the only place the
     * failure mode is reachable — and is a check with no reachability guesswork in it. Use
     * `java.util.Base64` and `kotlinx.serialization` instead; code that genuinely needs the
     * framework belongs in `src/androidTest`.
     */
    @Test
    fun jvmTestedCodeDoesNotUseTheStubbedAndroidApisThatFailSilently() {
        val testPaths = sourcesUnder(TEST_ROOT).map { it.relativePath }.toSet()
        val offenders = mainSources().filter { it.relativePath.removeSuffix(".kt") + "Test.kt" in testPaths }
            .flatMap { file ->
                IMPORT.findAll(file.readText()).map { it.groupValues[1] }
                    .filter { imported -> SILENTLY_STUBBED.any { imported == it || imported.startsWith("$it.") } }
                    .map { "${file.path}: import $it" }
                    .toList()
            }
        assertEquals(
            emptyList(), offenders,
            "These return defaults rather than throwing under isReturnDefaultValues.",
        )
    }

    // --- source tree -------------------------------------------------------------------------

    private class Source(val path: String, val relativePath: String, private val file: File) {
        fun readText(): String = file.readText()
    }

    private fun mainSources(): List<Source> = sourcesUnder(MAIN_ROOT)

    private fun sourcesUnder(root: String): List<Source> {
        val dir = listOf(File(root), File("app/$root")).firstOrNull { it.isDirectory }
        // Loud, not vacuous. A silently empty tree would make both tests above pass forever, which
        // is the failure mode this whole file exists to stop.
        assertNotNull(dir, "Could not locate $root from ${File(".").absolutePath}")
        return dir.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .map { Source(it.path, it.relativeTo(dir).invariantPath(), it) }
            .toList()
    }

    private fun File.invariantPath(): String = path.replace(File.separatorChar, '/')

    // --- the crude Kotlin reader these two rules need ----------------------------------------

    private class DataClass(val name: String, val parameters: String, private val body: String) {
        fun declaresOwnEquality(): Boolean =
            body.contains("override fun equals") && body.contains("override fun hashCode")
    }

    /**
     * Every `data class` header in [source], with its constructor parameter list and the text that
     * follows it.
     *
     * Balanced-paren scanning rather than a single regex: a parameter's own default value can
     * contain parentheses, and `[^)]*` stops at the first one. Deliberately not a Kotlin parser —
     * the rules above are about a declaration's shape, and a parser is a dependency this check does
     * not need.
     */
    private fun dataClassesIn(source: String): List<DataClass> =
        DATA_CLASS_HEADER.findAll(source).mapNotNull { match ->
            val open = match.range.last
            var depth = 0
            var i = open
            while (i < source.length) {
                when (source[i]) {
                    '(' -> depth++
                    ')' -> if (--depth == 0) break
                }
                i++
            }
            if (i >= source.length) return@mapNotNull null
            DataClass(
                name = match.groupValues[1],
                parameters = source.substring(open + 1, i),
                body = source.substring(i, minOf(source.length, i + BODY_SCAN_CHARS)),
            )
        }.toList()

    private companion object {
        const val MAIN_ROOT = "src/main/java"
        const val TEST_ROOT = "src/test/java"

        /** How far past a class header to look for hand-written equality overrides. Generous: the
         *  cost of over-reading is a false pass on one class, and the cost of under-reading is a
         *  build that fails on a class that did the right thing. */
        const val BODY_SCAN_CHARS = 1200

        val DATA_CLASS_HEADER = Regex("""\bdata class\s+(\w+)\s*\(""")
        val PARAM_IS_BYTE_ARRAY = Regex(""":\s*ByteArray""")
        val IMPORT = Regex("""^import\s+([\w.]+)""", RegexOption.MULTILINE)
        val SILENTLY_STUBBED = listOf("android.util.Base64", "org.json")
    }
}
