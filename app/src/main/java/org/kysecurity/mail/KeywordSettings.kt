package org.kysecurity.mail

import android.content.Context
import android.content.SharedPreferences

class KeywordSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    fun getAllKeywords(): Set<String> = prefs.getStringSet(KEY_ALL_KEYWORDS, emptySet()) ?: emptySet()

    /** Bounded both ways: keywords are unvalidated relay input rendered as un-recycled Chips. */
    fun rememberKeywords(keywords: Set<String>) {
        if (keywords.isEmpty()) return
        // Labels describe the user's mail: never persist them to this plaintext file in hostile mode.
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
        const val PREFS_NAME = "org.kysecurity.mail.keyword_settings"
        private const val KEY_ALL_KEYWORDS = "all_keywords"

        /** Long enough for any real mail label, short enough that the widest possible chip still
         *  measures cheaply. */
        internal const val MAX_KEYWORD_LENGTH = 64

        /** Chips are inflated one-per-entry with no recycling, on the main thread. */
        internal const val MAX_REMEMBERED_KEYWORDS = 200
    }
}
