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
     * `data class` + a key-material property means Kotlin generates identity `equals`/`hashCode`
     * while the type advertises structural equality — a silent trap on exactly the types that hold
     * key material, ciphertext and plaintext.
     *
     * A class that writes both overrides itself has made the decision deliberately and is allowed;
     * see `PgpDecryptor.DecryptResult.Ok`.
     *
     * The type list is not just `ByteArray`. It was, and that was the wrong half of the problem:
     * `ByteArray`'s generated `toString()` prints `[B@1f2e3d`, which leaks nothing, while
     * `SecretKeySpec` and `CharArray` sit in the same trap and `CredentialKeys` was carrying two of
     * the former the whole time this rule was green.
     */
    @Test
    fun noDataClassCarriesKeyMaterialWithoutOverridingEquality() {
        val offenders = mainSources().flatMap { file ->
            dataClassesIn(file.readText())
                .filter { PARAM_IS_KEY_MATERIAL.containsMatchIn(it.parameters) }
                .filterNot { it.declaresOwnEquality() }
                .map { "${file.path}: data class ${it.name}" }
        }
        assertEquals(
            emptyList(), offenders,
            "Use a plain class (or override equals/hashCode). See WrappedSecret and PinHash.",
        )
    }

    /**
     * A `data class` whose generated `toString()` would print a secret or a plaintext message body
     * must override it.
     *
     * **This is the half the `ByteArray` rule above never covered, and it is the half that leaks.**
     * `ByteArray.toString()` is an identity hash. `String.toString()` is the string — so
     * `DecryptedBody`, whose whole purpose is to hold a decrypted message, printed the entire mail
     * into any `Log.e(TAG, "...$outcome")` or crash-reporter frame that ever touched it. Nothing in
     * the tree does that today; the point is that adding the line is a one-token change and nothing
     * would have failed.
     *
     * Matched on **property name**, deliberately, because the type cannot answer this: `body:
     * String` and `serverUrl: String` are the same type and only one of them is mail. Crude, and
     * the same kind of crude as the reader below — a new field called `plaintext` that does not need
     * redacting is a two-second suppression, while a new field called `plaintext` that does is
     * exactly what this catches.
     */
    @Test
    fun noDataClassPrintsASecretOrAPlaintextBody() {
        val offenders = mainSources().flatMap { file ->
            dataClassesIn(file.readText())
                .filter { clazz -> clazz.parameterNames().any { it in SENSITIVE_PROPERTY_NAMES } }
                .filterNot { it.declaresOwnToString() }
                .map { clazz ->
                    val named = clazz.parameterNames().filter { it in SENSITIVE_PROPERTY_NAMES }
                    "${file.path}: data class ${clazz.name} (${named.joinToString()})"
                }
        }
        assertEquals(
            emptyList(), offenders,
            "Override toString() to redact. See PgpMimeReader.DecryptedBody.",
        )
    }

    /**
     * `isReturnDefaultValues` is now **false** (see app/build.gradle.kts), so these two throw at the
     * call rather than returning null and nothing *silently* — which is how `DeviceEnvelope`'s suite
     * once stayed green against a `= null` body. The runtime is therefore the primary control and
     * this rule is no longer the only thing standing between the two.
     *
     * It is kept, and it still earns its place: a throw is a failure in whichever test happens to
     * reach that line, reported as a mystery `RuntimeException` somewhere downstream. This names the
     * real problem — the wrong API in production code — at the file that has it, and it fires even
     * for a branch no test exercises.
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

    /**
     * A broad `catch` in coroutine code has to say something about cancellation.
     *
     * `kotlinx.coroutines.CancellationException` is an `Exception`, so `catch (e: Exception)` eats
     * it. In a `suspend` function that means a cancelled job does not unwind: it logs an error and
     * carries on, on a scope that is already dead. `DeviceContactRepository.syncAll` did exactly
     * that at five sites — cancelling a sync ran the four remaining stages anyway, holding the
     * contacts mutex and writing to ContactsContract — and `DeviceContactSyncWorker` caught the
     * same thing and reported it as a sync failure.
     *
     * `SecurityWipe.step` already states the rule: swallowing it is right "here and nowhere else",
     * because that one runs under `NonCancellable`. This is that sentence as a check.
     *
     * Deliberately file-scoped rather than function-scoped: matching a Kotlin function body with a
     * regex is how a rule like this ends up silently matching nothing. A file that declares a
     * `suspend fun` and catches broadly must *mention* `CancellationException` somewhere — as a
     * rethrow, or as a stated reason for not needing one. Coarse, and it is an over-approximation
     * in the safe direction: the failure mode is asking for a line of thought, never allowing one
     * to be skipped.
     */
    @Test
    fun broadCatchesInSuspendingFilesAddressCancellation() {
        val offenders = mainSources().filter { file ->
            val text = file.readText()
            "suspend fun" in text &&
                BROAD_CATCH.containsMatchIn(text) &&
                "CancellationException" !in text
        }.map { it.path }
        assertEquals(
            emptyList(), offenders,
            "catch (e: Exception) swallows CancellationException. Rethrow it, or say why this file need not.",
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

        fun declaresOwnToString(): Boolean = body.contains("override fun toString")

        /**
         * The declared property names, at the top level of the parameter list only.
         *
         * Depth-tracked so a default value that is itself a call with named arguments — or a
         * generic type argument — cannot contribute a name. `val` prefix required, so a plain
         * constructor parameter that is not a property is not matched either.
         */
        fun parameterNames(): List<String> {
            val names = mutableListOf<String>()
            var depth = 0
            var atTopLevelStart = true
            var index = 0
            while (index < parameters.length) {
                when (parameters[index]) {
                    '(', '<', '[' -> depth++
                    ')', '>', ']' -> depth--
                    ',' -> if (depth == 0) atTopLevelStart = true
                }
                if (depth == 0 && atTopLevelStart) {
                    val match = PROPERTY_DECL.find(parameters, index)
                    if (match != null && match.range.first <= index + LOOKAHEAD_CHARS) {
                        names += match.groupValues[1]
                        atTopLevelStart = false
                        index = match.range.last
                        continue
                    }
                }
                index++
            }
            return names
        }
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

        /** How far past a top-level comma a `val` may sit and still be that parameter's — covers
         *  annotations and modifiers (`@SerialName("x") val ...`, `internal val ...`). */
        const val LOOKAHEAD_CHARS = 200

        val DATA_CLASS_HEADER = Regex("""\bdata class\s+(\w+)\s*\(""")
        val PROPERTY_DECL = Regex("""\bval\s+(\w+)\s*:""")

        /**
         * Types whose generated `equals`/`hashCode` are identity-based while the declaration
         * advertises structure. `SecretKeySpec` is here because `CredentialKeys` held two.
         */
        val PARAM_IS_KEY_MATERIAL =
            Regex(""":\s*(ByteArray|CharArray|SecretKeySpec|SecretKey)\b""")

        /**
         * Property names that mean "this holds a secret or a plaintext message body".
         *
         * `publicKey` is deliberately ABSENT: it is public by construction, it is rendered in the
         * UI, and including it would have put a redaction requirement on eight DTOs that lose
         * nothing by printing.
         */
        val SENSITIVE_PROPERTY_NAMES = setOf(
            // Decrypted or cached message content.
            "plaintext", "body", "html", "plain", "preview", "protectedSubject", "encryptedPayload",
            // Credentials and key material.
            "secret", "deviceSecret", "pairingToken", "passphrase",
            "privateKey", "armoredPrivateKey",
        )
        // `pin` is deliberately ABSENT, and it is the one name that looks like it belongs. The only
        // `pin` property in the tree is `TlsPinState.Pinned.pin` — an SPKI hash of a *public*
        // certificate, which is useful in a log and secret from nobody. The app-lock PIN is never a
        // property: it lives in a `CharArray` that is passed, used and zeroed, so the key-material
        // rule above is what covers it.
        val IMPORT = Regex("""^import\s+([\w.]+)""", RegexOption.MULTILINE)
        val SILENTLY_STUBBED = listOf("android.util.Base64", "org.json")
        val BROAD_CATCH = Regex("""catch\s*\(\s*\w+\s*:\s*(Exception|Throwable)\s*\)""")
    }
}
