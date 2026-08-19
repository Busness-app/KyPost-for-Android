package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** A source-level check, not a runtime one: it reads PushPairingActivity.kt as text. */
class PairingDeepLinkConsumptionTest {

    @Test
    fun everyDeepLinkConsumptionSiteClearsTheIntent() {
        val source = pushPairingActivitySource()
        val lines = source.lines()

        val consumptionSites = lines.withIndex()
            .filter { (_, line) -> CONSUME_CALL.containsMatchIn(line) }
            .map { (index, _) -> index }

        // Two today: onCreateUnlocked and onNewIntent. A third would be a new way in, and the
        // point of counting is that it has to come here and be accounted for.
        assertEquals(
            "expected exactly two consumeDeepLink call sites; found ${consumptionSites.size}",
            2,
            consumptionSites.size,
        )

        val unguarded = consumptionSites.filterNot { site ->
            // The clear may sit a few lines below, past the comment that explains it.
            lines.subList(site + 1, minOf(lines.size, site + 1 + LINES_TO_LOOK_AHEAD))
                .any { CLEAR_STATEMENT.containsMatchIn(it) }
        }

        assertTrue(
            "consumeDeepLink at line(s) ${unguarded.map { it + 1 }} is not followed by " +
                "`intent.data = null`. A consumed deep link that stays on the Intent is replayed " +
                "by every recreation — see this class's KDoc.",
            unguarded.isEmpty(),
        )
    }

    private fun pushPairingActivitySource(): String {
        val relative = "src/main/java/org/kysecurity/mail/push/PushPairingActivity.kt"
        // Loud, not vacuous: a file this cannot find would make the assertions above pass forever,
        // which is the failure mode `SourceRulesTest` calls out in its own tree walk.
        val file = listOf(File(relative), File("app/$relative")).firstOrNull { it.isFile }
        requireNotNull(file) { "Could not locate $relative from ${File(".").absolutePath}" }
        return file.readText()
    }

    private companion object {
        /** Only the calls, never the declaration or a mention in prose. */
        val CONSUME_CALL = Regex("""(?<!fun )\bconsumeDeepLink\(""")
        val CLEAR_STATEMENT = Regex("""\bintent\.data\s*=\s*null""")

        /** Generous enough for the explanatory comment that sits between the two in onCreate. */
        const val LINES_TO_LOOK_AHEAD = 12
    }
}
