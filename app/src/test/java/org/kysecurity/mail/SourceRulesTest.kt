package org.kysecurity.mail

import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SourceRulesTest {

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

    private class DataClass(val name: String, val parameters: String, private val body: String) {
        fun declaresOwnEquality(): Boolean =
            body.contains("override fun equals") && body.contains("override fun hashCode")

        fun declaresOwnToString(): Boolean = body.contains("override fun toString")

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

        /** How far past a class header to look for equality overrides; generous on purpose. */
        const val BODY_SCAN_CHARS = 1200

        /** How far past a top-level comma a `val` may sit and still be that parameter's — covers
         *  annotations and modifiers (`@SerialName("x") val ...`, `internal val ...`). */
        const val LOOKAHEAD_CHARS = 200

        val DATA_CLASS_HEADER = Regex("""\bdata class\s+(\w+)\s*\(""")
        val PROPERTY_DECL = Regex("""\bval\s+(\w+)\s*:""")

        /** Types whose generated `equals`/`hashCode` are identity-based, not structural. */
        val PARAM_IS_KEY_MATERIAL =
            Regex(""":\s*(ByteArray|CharArray|SecretKeySpec|SecretKey)\b""")

        /** Names meaning "holds a secret or plaintext"; `publicKey` is deliberately absent. */
        val SENSITIVE_PROPERTY_NAMES = setOf(
            "plaintext", "body", "html", "plain", "preview", "protectedSubject", "encryptedPayload",
            "secret", "deviceSecret", "pairingToken", "passphrase",
            "privateKey", "armoredPrivateKey",
        )
        // `pin` is absent on purpose: the only `pin` property is an SPKI hash of a public cert.
        val IMPORT = Regex("""^import\s+([\w.]+)""", RegexOption.MULTILINE)
        val SILENTLY_STUBBED = listOf("android.util.Base64", "org.json")
    }
}
