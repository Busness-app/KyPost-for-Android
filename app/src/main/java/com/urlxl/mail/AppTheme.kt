package com.urlxl.mail

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

const val THEME_STORAGE_KEY = "kypost-theme"

val THEME_OPTIONS = listOf(
    "Dark Matter",
    "Light Matter",
    "Tropics",
    "Tropic Night",
    "Ocean",
    "Coffee",
    "White Cliffs",
    "Cyber Punk",
    "Neon Purple",
    "Space",
    "Sky",
    "Forest",
    "Sun",
    "Patina Ky",
    "Polished Ky",
)

data class ThemePalette(
    val bg: String,
    val panel: String,
    val ink: String,
    val inkStrong: String,
    val accent: String,
    val line: String,
    // Avatar gradient stops — mirrors web's ThemeVars newEmailStart/End/Border (used there for
    // the "compose" button gradient, reused here since .users-avatar/.contacts-avatar on web
    // draw from the same three fields).
    val avatarGradientStart: String,
    val avatarGradientEnd: String,
    val avatarBorder: String,
)

// Semantic colors are theme-invariant on web (fixed literals in styles.css, not per-theme
// palette fields) — mirrored here as constants rather than ThemePalette fields.
const val COLOR_DANGER = "#ff5f5f"
const val COLOR_DANGER_ACTION_BORDER = "#66FFB4AB" // rgba(255,180,171,.4)
const val COLOR_DANGER_ACTION_FILL = "#1FFFB4AB" // rgba(255,180,171,.12)
const val COLOR_DANGER_ACTION_TEXT = "#ffd8d3"
const val COLOR_WARNING = "#ffd64d"
const val COLOR_WARNING_ACTION_BORDER = "#66FFD64D" // rgba(255,214,77,.4)
const val COLOR_WARNING_ACTION_FILL = "#1FFFD64D" // rgba(255,214,77,.12)
const val COLOR_WARNING_ACTION_TEXT = "#fff0b8"
const val COLOR_SUCCESS_BORDER = "#7bbf7b"
const val COLOR_SUCCESS_TEXT = "#a5dca5"

private val themePalettes: Map<String, ThemePalette> = mapOf(
    "Dark Matter" to ThemePalette("#1a1a1e", "#252530", "#d4c5e2", "#e8ddf5", "#c29a72", "#404050", "#c29a72", "#9a7450", "#8f6b4a"),
    "Light Matter" to ThemePalette("#f5efe5", "#fff8ee", "#4c3d32", "#2d1f15", "#c29a72", "#c5b29d", "#c29a72", "#9a7450", "#8f6b4a"),
    "Tropics" to ThemePalette("#f4f1eb", "#fffaf0", "#43362d", "#241a14", "#9bc400", "#c4b7a3", "#9bc400", "#7ea100", "#78a100"),
    "Tropic Night" to ThemePalette("#15131a", "#221f2b", "#cdbde0", "#e8ddf5", "#9bc400", "#3c3650", "#9bc400", "#7ea100", "#78a100"),
    "Ocean" to ThemePalette("#0f1b24", "#152a36", "#b8d8e8", "#e0f2fb", "#5ea9be", "#2f5567", "#74bacd", "#4f91a6", "#4f91a6"),
    "Coffee" to ThemePalette("#1d1714", "#2a211d", "#d6c0b3", "#f0ded2", "#b47f5c", "#4a3830", "#b47f5c", "#8f5f42", "#8f5f42"),
    "White Cliffs" to ThemePalette("#f7f9fb", "#ffffff", "#2e4c63", "#163246", "#5ea8d8", "#8fc3df", "#4f9bc8", "#58b65a", "#2f7fb0"),
    "Cyber Punk" to ThemePalette("#120918", "#1e1028", "#f5d0ff", "#ffe9ff", "#00f5d4", "#5c2d84", "#00f5d4", "#00c9ad", "#00c9ad"),
    "Neon Purple" to ThemePalette("#130b1d", "#231233", "#e4ccff", "#f2e6ff", "#c86cff", "#63358a", "#c86cff", "#9d45d3", "#9d45d3"),
    "Space" to ThemePalette("#0b0f1a", "#151c2d", "#c8d5f0", "#e7efff", "#86a8ff", "#34496f", "#86a8ff", "#6788dd", "#6788dd"),
    "Sky" to ThemePalette("#dff1ff", "#f4fbff", "#2f4f64", "#183142", "#6db3d6", "#93bdd2", "#6db3d6", "#4f93b8", "#4f93b8"),
    "Forest" to ThemePalette("#142018", "#1f2f24", "#c7dbc7", "#e3f0df", "#8faa74", "#4f694f", "#8faa74", "#6f8d5a", "#6f8d5a"),
    "Sun" to ThemePalette("#fff3dc", "#fff9ec", "#5a4024", "#392611", "#e0ab4f", "#d4b27a", "#e0ab4f", "#bb8631", "#bb8631"),
    "Patina Ky" to ThemePalette("#0d0f14", "#161a22", "#64748b", "#e2e8f0", "#4deeea", "#1e293b", "#4deeea", "#10b981", "#0e9668"),
    "Polished Ky" to ThemePalette("#eef2f6", "#ffffff", "#475569", "#0f172a", "#0891b2", "#cbd5e1", "#0891b2", "#10b981", "#059669"),
)

fun getStoredThemeName(context: Context): String {
    val prefs = context.getSharedPreferences("com.urlxl.mail.settings", Context.MODE_PRIVATE)
    val saved = prefs.getString(THEME_STORAGE_KEY, "Patina Ky") ?: "Patina Ky"
    return if (THEME_OPTIONS.contains(saved)) saved else "Patina Ky"
}

fun saveThemeName(context: Context, themeName: String) {
    val prefs = context.getSharedPreferences("com.urlxl.mail.settings", Context.MODE_PRIVATE)
    prefs.edit().putString(THEME_STORAGE_KEY, themeName).apply()
}

fun getStoredThemePalette(context: Context): ThemePalette {
    return themePaletteFor(getStoredThemeName(context))
}

fun themePaletteFor(themeName: String): ThemePalette {
    return themePalettes[themeName] ?: themePalettes.getValue("Patina Ky")
}

fun applyThemeToActivity(activity: Activity) {
    val palette = getStoredThemePalette(activity)
    val bgColor = Color.parseColor(palette.bg)
    val panelColor = Color.parseColor(palette.panel)
    val accentColor = Color.parseColor(palette.accent)

    @Suppress("DEPRECATION")
    run {
        activity.window.statusBarColor = accentColor
        activity.window.navigationBarColor = panelColor
    }
    // Edge-to-edge (API 35+) ignores statusBarColor, leaving the raw window background (light by
    // default) visible behind the status bar. Paint the window itself so it matches the toolbar.
    activity.window.decorView.setBackgroundColor(accentColor)
    WindowInsetsControllerCompat(activity.window, activity.window.decorView).isAppearanceLightStatusBars =
        readableOn(accentColor) == Color.BLACK

    if (activity is AppCompatActivity) {
        activity.supportActionBar?.setBackgroundDrawable(ColorDrawable(accentColor))
        activity.supportActionBar?.title = styledTitle(activity.title?.toString().orEmpty(), readableOn(accentColor))
    }

    // The overflow ("more options") icon isn't part of the content view tree, so it never gets
    // painted by applyThemeToViewTree below. It defaults to a fixed light tint from the base
    // theme, which disappears against light accent colors (Sun, Sky, White Cliffs, ...). The menu
    // only exists once onCreateOptionsMenu has run, so defer the lookup by a frame.
    activity.window.decorView.post {
        tintOverflowIcon(activity, readableOn(accentColor))
    }

    val root: View = activity.findViewById(android.R.id.content)
    root.setBackgroundColor(bgColor)
    applyThemeToViewTree(root, palette)
}

/** Sets the action-bar title and repaints just its text color for the active palette, without
 *  re-theming the whole view tree (which would clobber custom backgrounds like the tab bar). */
fun applyThemedTitle(activity: Activity, title: CharSequence) {
    activity.title = title
    if (activity is AppCompatActivity) {
        val accent = Color.parseColor(getStoredThemePalette(activity).accent)
        activity.supportActionBar?.title = styledTitle(title.toString(), readableOn(accent))
    }
}

/** Pads the view's bottom by the system navigation-bar inset so edge-to-edge content (e.g. the
 *  bottom navigation bar) clears the gesture/nav area. */
fun applyBottomInset(view: View) {
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bottomInset = insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom
        v.setPadding(v.paddingLeft, v.paddingTop, v.paddingRight, basePaddingBottom + bottomInset)
        insets
    }
    ViewCompat.requestApplyInsets(view)
}

fun applyTopInsetWithHeader(activity: Activity, root: View) {
    val basePaddingLeft = root.paddingLeft
    val basePaddingTop = root.paddingTop
    val basePaddingRight = root.paddingRight
    val basePaddingBottom = root.paddingBottom

    ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
        val topInset = insets.getInsets(WindowInsetsCompat.Type.systemBars()).top
        // Under the enforced edge-to-edge of targetSdk 36, windowSoftInputMode="adjustResize" no
        // longer shrinks the window for the keyboard, so pad by the IME inset ourselves. It reads 0
        // whenever the keyboard is hidden, so screens without text fields are unaffected.
        val imeInset = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
        view.setPadding(
            basePaddingLeft,
            basePaddingTop + topInset + actionBarSize(activity),
            basePaddingRight,
            basePaddingBottom + imeInset,
        )
        insets
    }
    ViewCompat.requestApplyInsets(root)
}

fun applyPrimaryButtonTheme(context: Context, button: Button) {
    val palette = getStoredThemePalette(context)
    button.backgroundTintList = null
    button.background = buttonBackground(palette)
    button.setTextColor(readableOn(Color.parseColor(palette.accent)))
}

fun applyIconButtonTheme(context: Context, button: android.widget.ImageButton) {
    val palette = getStoredThemePalette(context)
    button.imageTintList = ColorStateList.valueOf(Color.parseColor(palette.inkStrong))
}

/** Transparent fill + 1dp `line` stroke, `inkStrong` text — mirrors web's `.notifications-ghost`.
 *  Use for secondary actions that shouldn't compete with a primary button (e.g. "Cancel"). */
fun applyGhostButtonTheme(context: Context, button: Button) {
    val palette = getStoredThemePalette(context)
    button.backgroundTintList = null
    button.background = ghostButtonBackground(palette)
    button.setTextColor(Color.parseColor(palette.inkStrong))
}

/** 1dp stroke + 12% fill of the fixed danger red, mirrors web's `.users-action-danger` /
 *  `.contacts-action-danger`. Use for destructive actions (delete), never theme-accent. */
fun applyDangerButtonTheme(context: Context, button: Button) {
    button.backgroundTintList = null
    button.background = dangerButtonBackground()
    button.setTextColor(Color.parseColor(COLOR_DANGER_ACTION_TEXT))
}

/** Stroke + 12%-fill warning panel for non-interactive informational callouts — same stroke+fill
 *  shape as [applyDangerButtonTheme] (STYLE_GUIDE.md §4's danger-button pattern), but with the
 *  fixed warning yellow (STYLE_GUIDE.md §1) and applied to a TextView since callouts aren't
 *  buttons. Caller sets its own padding/margins; this only sets background + text color. */
fun applyWarningCalloutTheme(context: Context, textView: TextView) {
    textView.background = warningCalloutBackground()
    textView.setTextColor(Color.parseColor(COLOR_WARNING_ACTION_TEXT))
}

/** Success/"added" state for the address-book picker's TO/CC/BCC action chips — mirrors
 *  [applyDangerButtonTheme]'s stroke+fill shape (STYLE_GUIDE.md §4's danger-button pattern is the
 *  closest documented precedent for a colored actionable state) using [COLOR_SUCCESS_BORDER]/
 *  [COLOR_SUCCESS_TEXT] (STYLE_GUIDE.md §1) instead of the danger palette.
 *
 *  [animate], when true, cross-fades from the chip's current colors instead of snapping
 *  (STYLE_GUIDE.md §5/§7 — 120ms). Only pass true from the actual tap that adds a recipient;
 *  per-bind calls (recycled rows) must stay instant, so the default is false. */
fun applySuccessChipTheme(
    context: Context,
    chip: com.google.android.material.chip.Chip,
    animate: Boolean = false,
) {
    val border = Color.parseColor(COLOR_SUCCESS_BORDER)
    val toBg = withAlpha(border, 0.12f)
    val toStroke = border
    val toText = Color.parseColor(COLOR_SUCCESS_TEXT)
    chip.chipStrokeWidth = 1f * context.resources.displayMetrics.density
    if (animate) {
        animateChipColorTransition(
            chip = chip,
            fromBg = chip.chipBackgroundColor?.defaultColor ?: toBg,
            toBg = toBg,
            fromStroke = chip.chipStrokeColor?.defaultColor ?: toStroke,
            toStroke = toStroke,
            fromText = chip.textColors?.defaultColor ?: toText,
            toText = toText,
        )
    } else {
        chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(toBg)
        chip.chipStrokeColor = android.content.res.ColorStateList.valueOf(toStroke)
        chip.setTextColor(toText)
    }
}

/** 120ms `FastOutSlowIn` cross-fade of a Chip's background/stroke/text colors — the shared motion
 *  timing all four sibling apps converged on independently (STYLE_GUIDE.md §5). Used for the one
 *  real color "snap" §7 calls out (the address-book chip's pill→success transition on tap); not
 *  wired into [applyPillChipTheme]'s checked/unchecked toggle, since Chip's own state machine
 *  already transitions that one and its colors are stateful `ColorStateList`s, not single values. */
fun animateChipColorTransition(
    chip: com.google.android.material.chip.Chip,
    fromBg: Int,
    toBg: Int,
    fromStroke: Int,
    toStroke: Int,
    fromText: Int,
    toText: Int,
    durationMs: Long = 120L,
) {
    val evaluator = android.animation.ArgbEvaluator()
    android.animation.ValueAnimator.ofFloat(0f, 1f).apply {
        duration = durationMs
        interpolator = androidx.interpolator.view.animation.FastOutSlowInInterpolator()
        addUpdateListener { animator ->
            val t = animator.animatedFraction
            chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(
                evaluator.evaluate(t, fromBg, toBg) as Int,
            )
            chip.chipStrokeColor = android.content.res.ColorStateList.valueOf(
                evaluator.evaluate(t, fromStroke, toStroke) as Int,
            )
            chip.setTextColor(evaluator.evaluate(t, fromText, toText) as Int)
        }
        start()
    }
}

/** Small uppercase, letter-spaced, 72%-opacity `inkStrong` label — mirrors web's
 *  `.sidebar-section-label` / `.contact-details-section-title`. Group headers only, not body
 *  copy or per-field captions. */
fun applySectionEyebrowLabel(context: Context, textView: TextView) {
    val palette = getStoredThemePalette(context)
    val inkStrong = Color.parseColor(palette.inkStrong)
    textView.isAllCaps = true
    textView.letterSpacing = 0.08f
    textView.textSize = 11f
    textView.setTextColor(withAlpha(inkStrong, 0.72f))
}

/** Stadium pill chip per the style guide's filter-tab spec: inactive = transparent fill + `line`
 *  stroke; active/checked = `accent` fill + `readableOn(accent)` text. Shared by the inbox's
 *  keyword filter pills and the compose screen's formatting toolbar.
 *
 *  The inactive fill can't actually be [Color.TRANSPARENT]: Chip's underlying ChipDrawable paints
 *  a private `chipSurfaceColor` layer (sourced from the theme's `colorSurface`, which this app
 *  hardcodes dark for popup/dialog chrome — see themes.xml) *underneath* `chipBackgroundColor`,
 *  with no public setter to override it. A transparent fill let that dark layer show through,
 *  rendering near-black text on a near-black chip in light themes (invisible in dark themes purely
 *  by coincidence, since dark-on-dark still looked intentional there). Painting an opaque `panel`
 *  fill instead — matching the bar behind the pills — fully covers that layer and reads as "blank"
 *  against the matching bar. */
fun applyPillChipTheme(context: Context, chip: com.google.android.material.chip.Chip) {
    val palette = getStoredThemePalette(context)
    val panel = Color.parseColor(palette.panel)
    val line = Color.parseColor(palette.line)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val accent = Color.parseColor(palette.accent)
    val onAccent = readableOn(accent)

    val checkedState = intArrayOf(android.R.attr.state_checked)
    val uncheckedState = intArrayOf(-android.R.attr.state_checked)
    val states = arrayOf(checkedState, uncheckedState)

    val contentColors = ColorStateList(states, intArrayOf(onAccent, inkStrong))

    chip.chipBackgroundColor = ColorStateList(states, intArrayOf(accent, panel))
    chip.setTextColor(contentColors)
    chip.chipStrokeColor = ColorStateList(states, intArrayOf(accent, line))
    chip.chipStrokeWidth = 1f * density
    chip.rippleColor = ColorStateList.valueOf(withAlpha(accent, 0.22f))
    chip.checkedIcon = null
    // Only tint, never clear: callers that pre-set `app:chipIcon` in XML (e.g. Compose's
    // icon-only formatting chips) want it recolored on every theme pass, same as the text color
    // above. Callers that never set one (the common case — keyword/attachment/plain-text pills)
    // are unaffected since chip.chipIcon stays null either way.
    if (chip.chipIcon != null) {
        chip.chipIconTint = contentColors
    }
}

/** Small solid circle — a minor "has unread content" cue, reused for both inbox rows and keyword
 *  pills so the two surfaces read as the same signal. Defaults to `accent`, but callers placing
 *  it on an already-accent-filled surface (e.g. a checked pill) should pass a contrasting
 *  [color] instead, or the dot disappears into its own background. */
fun unreadDotDrawable(context: Context, sizeDp: Int = 8, color: Int? = null): GradientDrawable {
    val palette = getStoredThemePalette(context)
    val sizePx = (sizeDp * density).toInt()
    return GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color ?: Color.parseColor(palette.accent))
        setSize(sizePx, sizePx)
    }
}

/** Pill-outline status badge with a small leading dot — STYLE_GUIDE.md §4's "status badge + dot"
 *  component (iOS `StatusBadgeView.swift` / Linux `StatusBadge.qml`; previously missing on
 *  Android, §7 item 2). [active] = fixed success green ([COLOR_SUCCESS_BORDER]/[COLOR_SUCCESS_TEXT],
 *  §1); inactive = theme-derived `line`/`panel`/`ink`, never a fixed gray (§1: "inactive status
 *  uses line/panel/ink from the active palette, not a fixed color"). Non-interactive — this reports
 *  state, it doesn't toggle it. */
fun applyStatusBadgeTheme(context: Context, chip: com.google.android.material.chip.Chip, active: Boolean) {
    val palette = getStoredThemePalette(context)
    val border: Int
    val text: Int
    val fill: Int
    if (active) {
        border = Color.parseColor(COLOR_SUCCESS_BORDER)
        text = Color.parseColor(COLOR_SUCCESS_TEXT)
        fill = withAlpha(border, 0.12f)
    } else {
        border = Color.parseColor(palette.line)
        text = Color.parseColor(palette.ink)
        fill = Color.parseColor(palette.panel)
    }
    chip.isCheckable = false
    chip.isClickable = false
    chip.isFocusable = false
    chip.chipBackgroundColor = ColorStateList.valueOf(fill)
    chip.chipStrokeColor = ColorStateList.valueOf(border)
    chip.chipStrokeWidth = 1f * density
    chip.setTextColor(text)
    chip.textSize = 12f
    chip.chipIcon = unreadDotDrawable(context, sizeDp = 7, color = border)
    chip.chipIconTint = null
    chip.chipIconSize = 7f * density
    chip.isChipIconVisible = true
}

/** Circular, two-stop gradient avatar with initials — mirrors web's `.users-avatar` /
 *  `.contacts-avatar`. [sizeDp] is 34dp for list rows, 52dp for a detail header per the guide. */
fun bindAvatar(context: Context, view: TextView, displayName: String, sizeDp: Int) {
    val palette = getStoredThemePalette(context)
    val accent = Color.parseColor(palette.accent)
    view.text = initialsOf(displayName)
    view.gravity = android.view.Gravity.CENTER
    view.setTextColor(readableOn(accent))
    view.background = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        intArrayOf(Color.parseColor(palette.avatarGradientStart), Color.parseColor(palette.avatarGradientEnd)),
    ).apply {
        shape = GradientDrawable.OVAL
        setStroke((1 * density).toInt(), Color.parseColor(palette.avatarBorder))
    }
    val sizePx = (sizeDp * density).toInt()
    view.layoutParams = (view.layoutParams ?: ViewGroup.LayoutParams(sizePx, sizePx)).apply {
        width = sizePx
        height = sizePx
    }
}

/** First letter of the first and last whitespace-separated word ("Ada Lovelace" -> "AL",
 *  "Cher" -> "C"), mirroring the initials web derives for the same avatar component. */
internal fun initialsOf(displayName: String): String {
    val words = displayName.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
    return when {
        words.isEmpty() -> ""
        words.size == 1 -> words[0].take(1).uppercase()
        else -> (words.first().take(1) + words.last().take(1)).uppercase()
    }
}

/** Dashed, accent-tinted-line, 10dp-radius background for a list's "nothing here yet" message —
 *  mirrors web's `.contacts-empty`. */
fun applyEmptyStateBackground(context: Context, view: View) {
    val palette = getStoredThemePalette(context)
    view.background = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setStroke(
            (1.5f * density).toInt(),
            blend(Color.parseColor(palette.line), Color.parseColor(palette.accent), 0.12f),
            6f * density,
            4f * density,
        )
    }
    val padH = (16 * density).toInt()
    view.setPadding(padH, padH, padH, padH)
}

// Wraps raw ttf bytes into a @font-face CSS block. Pure/testable — split out from
// [ibmPlexMonoFontFaceCss] so the encoding logic has a JVM unit test with no Android asset I/O.
internal fun buildMonoFontFaceCss(fontBytes: ByteArray): String {
    val base64 = java.util.Base64.getEncoder().encodeToString(fontBytes)
    return "@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:400;" +
        "src:url(data:font/ttf;base64,$base64) format('truetype');}"
}

private val monoFontFaceCssLock = Any()
@Volatile private var cachedMonoFontFaceCss: String? = null

/** Base64-inlined `@font-face` CSS for the bundled IBM Plex Mono Regular asset
 * (`assets/fonts/IBMPlexMono-Regular.ttf`), for injection into [EmailDetailActivity]'s WebView
 * HTML (STYLE_GUIDE.md §2/§7 item 1 — the email body previously rendered generic `monospace`).
 * Inlined rather than referenced via a `file:///android_asset/` base URL: that WebView renders
 * untrusted email HTML with JS enabled, and granting it `file://` origin access for a font is a
 * real security cost for a small convenience gain. Read once per process and cached — the ttf is
 * ~134KB, cheap to decode but no reason to repeat it on every email open.
 * ponytail: Regular weight only — email body isn't bold/italic-styled. Upgrade path: add more
 * weights + font-weight variants here if the renderer ever needs them. */
fun ibmPlexMonoFontFaceCss(context: Context): String {
    cachedMonoFontFaceCss?.let { return it }
    synchronized(monoFontFaceCssLock) {
        cachedMonoFontFaceCss?.let { return it }
        val bytes = context.applicationContext.assets
            .open("fonts/IBMPlexMono-Regular.ttf")
            .use { it.readBytes() }
        val css = buildMonoFontFaceCss(bytes)
        cachedMonoFontFaceCss = css
        return css
    }
}

private fun tintOverflowIcon(activity: Activity, color: Int) {
    val description = activity.getString(androidx.appcompat.R.string.abc_action_menu_overflow_description)
    val overflowButton = findViewByContentDescription(activity.window.decorView, description) as? ImageView
    overflowButton?.imageTintList = ColorStateList.valueOf(color)
}

private fun findViewByContentDescription(view: View, description: CharSequence): View? {
    if (view.contentDescription == description) return view
    if (view is ViewGroup) {
        for (index in 0 until view.childCount) {
            findViewByContentDescription(view.getChildAt(index), description)?.let { return it }
        }
    }
    return null
}

private fun applyThemeToViewTree(view: View, palette: ThemePalette) {
    val panelColor = Color.parseColor(palette.panel)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val ink = Color.parseColor(palette.ink)
    val accent = Color.parseColor(palette.accent)

    when (view) {
        is EditText -> {
            view.setTextColor(inkStrong)
            view.setHintTextColor(ink)
            view.background = fieldBackground(palette)
            // A bare GradientDrawable carries no internal padding, so without this the text and
            // hint sit flush against the rounded border. Preserve any larger top padding a
            // multi-line field (e.g. the compose body) already declares.
            val padH = (14 * density).toInt()
            val padV = (12 * density).toInt()
            view.setPadding(padH, maxOf(padV, view.paddingTop), padH, maxOf(padV, view.paddingBottom))
        }
        is Button -> {
            view.setTextColor(readableOn(accent))
            view.background = buttonBackground(palette)
        }
        is CheckBox -> {
            view.setTextColor(inkStrong)
            view.buttonTintList = ColorStateList.valueOf(accent)
        }
        is TextView -> {
            // Hardcoded XML text colors in this app are always grayscale template leftovers
            // (black/white/mid-gray placeholders), never intentional brand colors, so any
            // grayscale color is safe to remap onto the active palette's ink tones.
            val current = view.currentTextColor
            if (isGrayscale(current)) {
                view.setTextColor(if (isNearWhite(current) || isNearBlack(current)) inkStrong else ink)
            }
        }
    }

    if (view is ViewGroup) {
        // The inbox list themes its own item views (rounded CardViews) in the adapter. Recursing
        // into it here would overwrite each card's rounded background with a flat ColorDrawable,
        // and since only already-bound rows get hit the rounding ends up inconsistent. Skip its
        // whole subtree.
        if (view is androidx.recyclerview.widget.RecyclerView) {
            return
        }
        // Keep panel containers in sync with the active palette. Always repaint (not just when
        // background == null) so switching themes without recreating the activity refreshes
        // containers that were already painted on a previous pass, not just newly-touched ones.
        view.setBackgroundColor(panelColor)
        for (index in 0 until view.childCount) {
            applyThemeToViewTree(view.getChildAt(index), palette)
        }
    }
}

private val density: Float get() = android.content.res.Resources.getSystem().displayMetrics.density

/** Pure dp->px math, factored out of [dpToPx] so it's unit-testable without the Android
 *  framework (this project has no Robolectric setup) — [dpToPx] is the entry point every caller
 *  should use directly. */
internal fun scalePxByDensity(value: Int, density: Float): Int = (value * density).toInt()

/** Converts a dp value to raw device pixels using the system-wide [density] snapshot — for raw
 *  View APIs (setPadding, LayoutParams margins) that take pixels, not dp. */
fun dpToPx(value: Int): Int = scalePxByDensity(value, density)

/** Adds [view] with vertical breathing room ([topDp]/[bottomDp], converted via [dpToPx]) instead
 *  of the zero-margin default plain `addView(view)` produces — the Security/Keyword settings
 *  screens build their layout by hand and need real gaps between sibling controls. */
fun LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0) {
    val params = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        topMargin = dpToPx(topDp)
        bottomMargin = dpToPx(bottomDp)
    }
    addView(view, params)
}

private fun panelBackground(context: Context, palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = context.resources.getDimension(R.dimen.card_corner_radius)
        setColor(Color.parseColor(palette.panel))
    }
}

/**
 * Paints [view]'s background as a rounded, theme-`panel`-colored panel using the shared
 * STYLE_GUIDE.md §3 Card/panel radius (`@dimen/card_corner_radius`). For containers that need a
 * *rounded* panel fill rather than the flat fill `applyThemeToViewTree` gives generic ViewGroups.
 */
fun applyPanelBackground(context: Context, view: View) {
    view.background = panelBackground(context, getStoredThemePalette(context))
}

private fun fieldBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 14f * density
        setColor(Color.parseColor(palette.panel))
        setStroke((2 * density).toInt(), Color.parseColor(palette.line))
    }
}

private fun buttonBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.parseColor(palette.accent))
    }
}

private fun ghostButtonBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.TRANSPARENT)
        setStroke((1 * density).toInt(), Color.parseColor(palette.line))
    }
}

private fun dangerButtonBackground(): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.parseColor(COLOR_DANGER_ACTION_FILL))
        setStroke((1 * density).toInt(), Color.parseColor(COLOR_DANGER_ACTION_BORDER))
    }
}

private fun warningCalloutBackground(): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.parseColor(COLOR_WARNING_ACTION_FILL))
        setStroke((1 * density).toInt(), Color.parseColor(COLOR_WARNING_ACTION_BORDER))
    }
}

private fun styledTitle(title: String, color: Int): SpannableString {
    return SpannableString(title).apply {
        setSpan(ForegroundColorSpan(color), 0, length, 0)
    }
}

/** Returns black or white — whichever reads more legibly on the given background color. */
internal fun readableOn(backgroundColor: Int): Int {
    val darkness = 1 - (0.299 * Color.red(backgroundColor) + 0.587 * Color.green(backgroundColor) + 0.114 * Color.blue(backgroundColor)) / 255
    return if (darkness >= 0.45) Color.WHITE else Color.BLACK
}

/** True when [palette]'s background is dark enough that white text reads better on it than black —
 *  i.e. this is one of the app's "dark" themes (Dark Matter, Tropic Night, Ocean, ...) rather than a
 *  light one. Used by [com.urlxl.mail.EmailDetailActivity] to decide whether rendered email HTML
 *  needs its own colors forcibly overridden: a light theme's palette already looks like a typical
 *  email's default white-background/dark-text design, so nothing needs overriding there, but a dark
 *  theme's palette does not, and most email HTML hardcodes its own light-mode colors regardless of
 *  the reader's OS/app theme. */
internal fun isDarkPalette(palette: ThemePalette): Boolean = readableOn(Color.parseColor(palette.bg)) == Color.WHITE

private fun isNearWhite(color: Int): Boolean {
    return Color.red(color) > 235 && Color.green(color) > 235 && Color.blue(color) > 235
}

private fun isNearBlack(color: Int): Boolean {
    return Color.red(color) < 20 && Color.green(color) < 20 && Color.blue(color) < 20
}

/** Returns [color] with its alpha channel scaled by [fraction] (0f–1f). */
internal fun withAlpha(color: Int, fraction: Float): Int {
    val alpha = (Color.alpha(color) * fraction).toInt().coerceIn(0, 255)
    return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
}

/** Linearly interpolates from [base] towards [tint] by [fraction] (0f = base, 1f = tint). */
internal fun blend(base: Int, tint: Int, fraction: Float): Int {
    return Color.rgb(
        (Color.red(base) + (Color.red(tint) - Color.red(base)) * fraction).toInt(),
        (Color.green(base) + (Color.green(tint) - Color.green(base)) * fraction).toInt(),
        (Color.blue(base) + (Color.blue(tint) - Color.blue(base)) * fraction).toInt(),
    )
}

private fun isGrayscale(color: Int): Boolean {
    val r = Color.red(color)
    val g = Color.green(color)
    val b = Color.blue(color)
    return (maxOf(r, g, b) - minOf(r, g, b)) <= 10
}

private fun actionBarSize(activity: Activity): Int {
    val typedArray = activity.theme.obtainStyledAttributes(intArrayOf(android.R.attr.actionBarSize))
    return try {
        typedArray.getDimensionPixelSize(0, 0)
    } finally {
        typedArray.recycle()
    }
}
