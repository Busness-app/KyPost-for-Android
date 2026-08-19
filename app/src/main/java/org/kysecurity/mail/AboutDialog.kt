package org.kysecurity.mail

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.Layout
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.AlignmentSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.text.style.TypefaceSpan
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import java.util.Calendar

const val APP_VERSION = BuildConfig.VERSION_NAME

fun showAboutDialog(activity: Activity) {
    val palette = getStoredThemePalette(activity)
    val panel = Color.parseColor(palette.panel)
    val bg = Color.parseColor(palette.bg)
    val ink = Color.parseColor(palette.ink)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val accent = Color.parseColor(palette.accent)
    val line = Color.parseColor(palette.line)
    val density = activity.resources.displayMetrics.density

    fun dp(value: Int) = (value * density).toInt()

    val container = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(24), dp(24), dp(24), dp(20))
    }

    val headerRow = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }
    val heading = TextView(activity).apply {
        text = activity.getString(R.string.about_title)
        setTextColor(inkStrong)
        setTypeface(typeface, Typeface.BOLD)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
    }
    headerRow.addView(heading)

    val versionBadge = TextView(activity).apply {
        text = activity.getString(R.string.about_version_badge, APP_VERSION)
        setTextColor(readableOn(accent))
        setTypeface(typeface, Typeface.BOLD)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        setPadding(dp(10), dp(3), dp(10), dp(3))
        background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(100).toFloat()
            setColor(accent)
        }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { marginStart = dp(10) }
    }
    headerRow.addView(versionBadge)
    container.addView(headerRow)

    val currentYear = Calendar.getInstance().get(Calendar.YEAR).toString()
    val about = TextView(activity).apply {
        text = activity.getString(R.string.about_body, currentYear)
        setTextColor(ink)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setLineSpacing(dp(4).toFloat(), 1f)
        setPadding(0, dp(10), 0, 0)
    }
    container.addView(about)

    val divider = View(activity).apply {
        setBackgroundColor(accent)
        alpha = 0.5f
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(2)
        ).apply {
            topMargin = dp(20)
            bottomMargin = dp(16)
        }
    }
    container.addView(divider)

    val licenseLabel = TextView(activity).apply {
        text = activity.getString(R.string.about_license_label)
        setTextColor(accent)
        setTypeface(typeface, Typeface.BOLD)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        letterSpacing = 0.08f
        setPadding(0, 0, 0, dp(10))
    }
    container.addView(licenseLabel)

    val license = TextView(activity).apply {
        text = formatLicenseText(readLicenseText(activity))
        setTextColor(ink)
        setTextIsSelectable(true)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
        setLineSpacing(dp(3).toFloat(), 1f)
        setPadding(dp(16), dp(16), dp(16), dp(16))
    }
    val boxHeight = (activity.resources.displayMetrics.heightPixels * 0.42f).toInt()
    val licenseBox = ScrollView(activity).apply {
        addView(license)
        isVerticalScrollBarEnabled = true
        background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = 14f * density
            setColor(bg)
            setStroke(dp(2), line)
        }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            boxHeight
        )
    }
    container.addView(licenseBox)

    val closeButton = Button(activity).apply {
        text = activity.getString(android.R.string.ok)
        isAllCaps = false
        setTypeface(typeface, Typeface.BOLD)
        applyPrimaryButtonTheme(activity, this)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            gravity = Gravity.END
            topMargin = dp(20)
            marginStart = dp(24)
        }
        minWidth = dp(96)
    }
    container.addView(closeButton)

    val dialog = AlertDialog.Builder(activity)
        .setView(container)
        .create()

    closeButton.setOnClickListener { dialog.dismiss() }

    dialog.setOnShowListener {
        // Paint the dialog surface to match the active palette; the base AlertDialog background is
        // otherwise a fixed light card that clashes with the dark themes.
        dialog.window?.setBackgroundDrawable(GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = 20f * density
            setColor(panel)
            setStroke(dp(1), line)
        })
    }
    dialog.show()
}

private fun readLicenseText(context: Context): String {
    return context.resources.openRawResource(R.raw.gpl_license)
        .bufferedReader()
        .use { it.readText() }
}

/** Reflows the print-wrapped GPL text for the screen; the wording itself is never altered. */
private fun formatLicenseText(raw: String): CharSequence {
    val builder = SpannableStringBuilder()
    val blocks = mutableListOf<List<String>>()
    val current = mutableListOf<String>()
    for (line in raw.lines()) {
        if (line.isBlank()) {
            if (current.isNotEmpty()) {
                blocks.add(current.toList())
                current.clear()
            }
        } else {
            current.add(line)
        }
    }
    if (current.isNotEmpty()) blocks.add(current.toList())

    blocks.forEachIndexed { index, block ->
        if (index > 0) builder.append("\n\n")
        val firstIndent = block.first().indentWidth()
        val minIndent = block.minOf { it.indentWidth() }
        val start = builder.length
        when {
            // Centered headings: deep leading indent, never true for prose (0-2) or samples (4).
            firstIndent >= 8 -> {
                builder.append(block.joinToString("\n") { it.trim() })
                builder.setSpan(
                    AlignmentSpan.Standard(Layout.Alignment.ALIGN_CENTER),
                    start, builder.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
                builder.setSpan(StyleSpan(android.graphics.Typeface.BOLD), start, builder.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            // Indented sample/notice blocks: whitespace matters, keep verbatim in monospace.
            minIndent >= 4 -> {
                builder.append(block.joinToString("\n") { it.drop(minIndent) })
                builder.setSpan(TypefaceSpan("monospace"), start, builder.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                builder.setSpan(RelativeSizeSpan(0.9f), start, builder.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            // Prose: unwrap the print-time hard breaks so the paragraph flows to the box width.
            else -> {
                builder.append(block.joinToString(" ") { it.trim() })
            }
        }
    }
    return builder
}

private fun String.indentWidth(): Int = takeWhile { it == ' ' }.length
