package org.kysecurity.mail

import android.content.Context
import android.content.SharedPreferences

class KeywordSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    fun getAllKeywords(): Set<String> = prefs.getStringSet(KEY_ALL_KEYWORDS, emptySet()) ?: emptySet()

    /**
     * Merges newly-seen keywords into the remembered set, bounded on both axes.
     *
     * Keywords are the relay's per-message `label`, which is unvalidated server input, and this set
     * is rendered as one un-recycled `Chip` per entry during `InboxActivity.onCreate`. Unbounded,
     * a single inbox response could brick the app: ~50k labels reproducibly threw
     * `OutOfMemoryError` inside `onCreate` (measured: ~17k chips in ~14s before the throw), and one
     * 20MB label consumed most of the heap just loading this file. The Keyword Settings screen —
     * the only place a user could clean up — dies the same way, and this file outlives unpairing,
     * so there was no in-app recovery at all.
     *
     * Eviction is oldest-first, which keeps the labels the user has seen most recently.
     */
    fun rememberKeywords(keywords: Set<String>) {
        if (keywords.isEmpty()) return
        // Server-assigned labels describe the user's mail, so under Hostile Location Protection
        // they must not be written to this plaintext file. Tabs still work for the session from
        // whatever the current fetch returned; only the accumulated history is skipped.
        if (hostileLocationSettings.isEnabled()) return
        val cleaned = keywords.asSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && it.length <= MAX_KEYWORD_LENGTH }
            .toSet()
        if (cleaned.isEmpty()) return
        // LinkedHashSet: insertion-ordered, so takeLast() drops the oldest entries.
        val merged = LinkedHashSet(getAllKeywords()).apply { addAll(cleaned) }
        val capped = if (merged.size <= MAX_REMEMBERED_KEYWORDS) {
            merged
        } else {
            LinkedHashSet(merged.toList().takeLast(MAX_REMEMBERED_KEYWORDS))
        }
        prefs.edit().putStringSet(KEY_ALL_KEYWORDS, capped).apply()
    }

    fun isKeywordVisible(keyword: String): Boolean = prefs.getBoolean(keyForVisibility(keyword), true)

    fun setKeywordVisible(keyword: String, visible: Boolean) {
        prefs.edit().putBoolean(keyForVisibility(keyword), visible).apply()
    }

    fun filterVisible(keywords: Set<String>): Set<String> {
        return keywords.filter { isKeywordVisible(it) }.toSet()
    }

    private fun keyForVisibility(keyword: String): String = "keyword_visible_$keyword"

    companion object {
        /** Public so [org.kysecurity.mail.security.SecurityWipe] and
         *  [org.kysecurity.mail.push.PushRepository.clearPairing] can clear this file by name rather
         *  than repeating the literal. */
        const val PREFS_NAME = "org.kysecurity.mail.keyword_settings"
        private const val KEY_ALL_KEYWORDS = "all_keywords"

        /** Long enough for any real mail label, short enough that the widest possible chip still
         *  measures cheaply. */
        internal const val MAX_KEYWORD_LENGTH = 64

        /** Chips are inflated one-per-entry with no recycling, on the main thread. */
        internal const val MAX_REMEMBERED_KEYWORDS = 200
    }
}
