package com.urlxl.mail

import android.os.Bundle
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.urlxl.mail.security.LockedActivity

class KeywordSettingsActivity : LockedActivity() {

    private lateinit var keywordSettings: KeywordSettings

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return

        keywordSettings = KeywordSettings(this)
        setTitle(R.string.keyword_settings_title)

        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }

        applyTopInsetWithHeader(this, scrollView)

        val intro = TextView(this).apply {
            text = getString(R.string.keyword_settings_intro)
            textSize = 14f
        }
        container.addViewSpaced(intro, bottomDp = 16)

        val allKeywords = keywordSettings.getAllKeywords().sorted()
        if (allKeywords.isEmpty()) {
            val emptyView = TextView(this).apply {
                text = getString(R.string.keyword_settings_empty)
                textSize = 14f
            }
            applyEmptyStateBackground(this, emptyView)
            container.addViewSpaced(emptyView, bottomDp = 12)
        } else {
            allKeywords.forEach { keyword ->
                val checkbox = CheckBox(this).apply {
                    text = keyword
                    isChecked = keywordSettings.isKeywordVisible(keyword)
                    textSize = 15f
                    setOnCheckedChangeListener { _, isChecked ->
                        keywordSettings.setKeywordVisible(keyword, isChecked)
                    }
                }
                container.addViewSpaced(checkbox, bottomDp = 12)
            }
        }

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)
    }
}
