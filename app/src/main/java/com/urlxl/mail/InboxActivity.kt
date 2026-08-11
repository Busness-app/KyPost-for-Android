package com.urlxl.mail

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.urlxl.mail.mail.FolderInfo
import com.urlxl.mail.mail.MailFetchResult
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.MailRepository
import com.urlxl.mail.mail.MailRuntime
import com.urlxl.mail.mail.isFlaggedPhishing
import com.urlxl.mail.mail.userFacingMessage
import com.urlxl.mail.pgp.PgpKeyActivity
import com.urlxl.mail.push.PushNotificationDispatcher
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import com.urlxl.mail.security.LockedActivity

class InboxActivity : LockedActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var keywordChipScroll: View
    private lateinit var keywordChips: ChipGroup
    private lateinit var bottomNav: BottomNavigationView
    private lateinit var loadingOverlay: View
    private lateinit var swipeRefresh: androidx.swiperefreshlayout.widget.SwipeRefreshLayout
    private lateinit var loadingStatus: TextView
    private lateinit var cancelLoading: View
    private lateinit var inboxRoot: View
    private lateinit var inboxContent: View
    private lateinit var headerFolderTitle: TextView
    private lateinit var adapter: EmailAdapter
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var mailRepository: MailRepository
    private lateinit var keywordSettings: KeywordSettings
    private var currentFolder = "INBOX"
    private var lastAppliedThemeName: String = ""

    private var selectedTab = KeywordTabs.ALL
    // BottomNavigationView routes setSelectedItemId() through the RESELECTED listener (not the
    // SELECTED listener) whenever the target item is already selected — and nav_inbox is always
    // the selected item here, since nav_compose/nav_contacts return false to avoid stealing
    // selection (see the comment on that below). So both listener branches below must check this
    // flag, and it must be raised around every programmatic `bottomNav.selectedItemId = R.id.nav_inbox`
    // assignment, or that assignment re-enters the reselected listener and reopens the popup
    // (this broke cold launch and post-pick behavior before this flag was added).
    private var suppressFolderPickerReentry = false
    private var allEmails: List<Email> = emptyList()
    private var pendingMessageId: String? = null
    private var pendingSender: String? = null
    private var pendingSubject: String? = null
    private var pendingMessageDeadlineMs: Long = 0L

    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshInbox()
            scheduleNextRefresh()
        }
    }

    // The backend can take a few seconds to make a just-pushed email available via the inbox
    // fetch — a single refresh attempt right after the notification tap routinely misses it, so
    // this keeps polling (bounded by pendingMessageDeadlineMs) instead of giving up immediately.
    private val pendingMessagePollRunnable = Runnable { refreshInbox() }

    private val emailDetailLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val removedId = result.data?.getStringExtra(EmailDetailActivity.EXTRA_REMOVED_EMAIL_ID)
            if (removedId != null) {
                allEmails = allEmails.filter { it.id != removedId }
                renderFilteredEmails()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return
        setContentView(R.layout.activity_inbox)
        applyThemeToActivity(this)
        lastAppliedThemeName = getStoredThemeName(this)

        mailRepository = MailRuntime.graph(this).repository
        keywordSettings = KeywordSettings(this)

        initViews()
        supportActionBar?.setDisplayShowTitleEnabled(false)
        applyFolderTitle()
        applyTopInsetWithHeader(this, headerFolderTitle)
        applyBottomInset(bottomNav)
        applyInboxThemeChrome()
        setupRecyclerView()
        setupTabs()
        setupBottomNav()
        setupSwipeGestures()

        val msgId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID)
        if (msgId != null) {
            setPendingMessage(
                msgId,
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER),
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT),
            )
            currentFolder = "INBOX"
        }
    }

    private fun setPendingMessage(msgId: String, sender: String?, subject: String?) {
        pendingMessageId = msgId
        pendingSender = sender
        pendingSubject = subject
        pendingMessageDeadlineMs = System.currentTimeMillis() + PENDING_MESSAGE_TIMEOUT_MS
    }

    private fun applyFolderTitle() {
        val folderLabel = when {
            currentFolder == "Junk" -> getString(R.string.nav_junk)
            currentFolder == "Trash" -> getString(R.string.nav_trash)
            currentFolder.startsWith("$ARCHIVE_PARENT_FOLDER/") -> currentFolder.substringAfterLast('/')
            else -> getString(R.string.nav_inbox)
        }
        val title = getString(R.string.inbox_heading, folderLabel)
        applyThemedTitle(this, title)
        headerFolderTitle.text = title
    }

    override fun onStart() {
        super.onStart()
        if (redirectedToUnlock) return
        refreshInbox()
        scheduleNextRefresh()
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return

        val currentTheme = getStoredThemeName(this)
        if (currentTheme != lastAppliedThemeName) {
            recreate()
            return
        }

        applyThemeToActivity(this)
        applyInboxThemeChrome()
        adapter.notifyDataSetChanged()
        rebuildTabs(allEmails)
        renderFilteredEmails()
    }

    override fun onStop() {
        super.onStop()
        if (redirectedToUnlock) return
        mainHandler.removeCallbacks(refreshRunnable)
        mainHandler.removeCallbacks(pendingMessagePollRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
    }

    private fun initViews() {
        inboxRoot = findViewById(R.id.inboxRoot)
        inboxContent = findViewById(R.id.inboxContent)
        headerFolderTitle = findViewById(R.id.headerFolderTitle)
        recyclerView = findViewById(R.id.recyclerViewInbox)
        keywordChipScroll = findViewById(R.id.keywordChipScroll)
        keywordChips = findViewById(R.id.keywordChipGroup)
        bottomNav = findViewById(R.id.bottomNavigation)
        loadingOverlay = findViewById(R.id.loadingOverlay)
        swipeRefresh = findViewById(R.id.inboxSwipeRefresh)
        // forceFullResync = true: the 90-second cadence sends the cursor and gets a delta, which
        // cannot repair a drifted cache. Someone pulling down is saying they think the list is
        // wrong, so this re-reads the folder rather than asking what changed.
        swipeRefresh.setOnRefreshListener { refreshInbox(forceFullResync = true) }
        loadingStatus = findViewById<TextView>(R.id.loadingStatus)
        cancelLoading = findViewById(R.id.cancelLoading)

        cancelLoading.setOnClickListener {
            pendingMessageId = null
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            loadingOverlay.visibility = View.GONE
        }
    }

    private fun applyInboxThemeChrome() {
        val palette = getStoredThemePalette(this)
        val bg = Color.parseColor(palette.bg)
        val panel = Color.parseColor(palette.panel)
        val ink = Color.parseColor(palette.ink)
        val inkStrong = Color.parseColor(palette.inkStrong)
        val accent = Color.parseColor(palette.accent)

        inboxRoot.setBackgroundColor(bg)
        inboxContent.setBackgroundColor(bg)
        recyclerView.setBackgroundColor(bg)

        headerFolderTitle.setTextColor(inkStrong)

        // Rounded panel bar behind the keyword pills — shared STYLE_GUIDE.md §3 Card/panel radius.
        applyPanelBackground(this, keywordChipScroll)

        // Re-style every existing chip in place so a theme switch recolors them even when
        // rebuildTabs() short-circuits because the keyword set itself hasn't changed.
        for (index in 0 until keywordChips.childCount) {
            (keywordChips.getChildAt(index) as? Chip)?.let { styleKeywordChip(it) }
        }

        bottomNav.backgroundTintList = null
        bottomNav.setBackgroundColor(panel)
        val states = arrayOf(
            intArrayOf(android.R.attr.state_checked),
            intArrayOf()
        )
        val colors = intArrayOf(inkStrong, ink)
        val list = ColorStateList(states, colors)
        bottomNav.itemTextColor = list
        bottomNav.itemIconTintList = list
        bottomNav.itemRippleColor = ColorStateList.valueOf(adjustAlpha(accent, 0.20f))
        bottomNav.itemActiveIndicatorColor = ColorStateList.valueOf(adjustAlpha(accent, 0.30f))
    }

    private fun adjustAlpha(color: Int, factor: Float): Int {
        val alpha = (Color.alpha(color) * factor).toInt().coerceIn(0, 255)
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (redirectedToUnlock) return
        setIntent(intent)
        val msgId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID)
        if (msgId != null) {
            setPendingMessage(
                msgId,
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER),
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT),
            )
            currentFolder = "INBOX"
            applyFolderTitle()
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            refreshInbox()
        }
    }

    private fun setupRecyclerView() {
        adapter = EmailAdapter(emptyList()) { email ->
            openEmailDetail(email)
        }
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
    }

    private fun openEmailDetail(email: Email) {
        val intent = Intent(this, EmailDetailActivity::class.java)
        intent.putExtra("email_id", email.id)
        intent.putExtra("email_subject", email.subject)
        intent.putExtra("email_sender", email.sender)
        intent.putExtra("email_preview", email.preview)
        intent.putExtra("email_body_mode", email.bodyMode)
        intent.putExtra("email_folder", currentFolder)
        intent.putExtra("email_has_attachments", email.hasAttachments)
        intent.putExtra("email_pgp_encrypted", email.pgpEncrypted)
        intent.putExtra("email_pgp_decrypt_error", email.pgpDecryptError)
        // Signature state is the only signal that separates an authentic signed message from an
        // impersonation. The relay computes it and it was persisted to Room behind its own
        // migration, but it stopped here — so a forged-signature message rendered with the
        // reassuring "this message was encrypted" bar and nothing else.
        intent.putExtra("email_pgp_signed", email.pgpSigned)
        intent.putExtra("email_pgp_verified", email.pgpVerified)
        intent.putExtra("email_pgp_signer_fingerprint", email.pgpSignerFingerprint)
        // The $Phishing IMAP keyword the server sets on mail that impersonates
        // KyPost. See mail/PhishingFlag.kt for why the match is
        // case-insensitive.
        intent.putExtra("email_suspicious", isFlaggedPhishing(email.keywords))
        emailDetailLauncher.launch(intent)
    }

    private fun checkPendingMessage(emails: List<Email>, isFinal: Boolean = false) {
        val id = pendingMessageId ?: return
        
        // Match by ID first, then fallback to fuzzy match by sender + subject if IDs don't match
        // (common in IMAP where push messageId might be a server UUID but email.id is header Message-ID).
        // The fallback requires a non-blank sender: `contains("")` is always true, so a push payload
        // with an empty senderName silently reduced this to subject-only matching and let whoever
        // composes the payload open — and mark read — an arbitrary other cached message whose
        // subject they could guess.
        val email = emails.find { it.id == id }
            ?: pendingSender
                ?.takeIf { it.isNotBlank() }
                ?.let { sender ->
                    emails.find { it.sender.contains(sender, ignoreCase = true) && it.subject == pendingSubject }
                }

        if (email != null) {
            pendingMessageId = null
            pendingSender = null
            pendingSubject = null
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            openEmailDetail(email)
            return
        }

        if (!isFinal) return

        if (System.currentTimeMillis() < pendingMessageDeadlineMs) {
            // Not found on this attempt, but still within the deep-link wait window — the backend
            // may not have indexed the just-arrived email yet. Poll again shortly instead of
            // giving up after a single miss.
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            mainHandler.postDelayed(pendingMessagePollRunnable, PENDING_MESSAGE_POLL_INTERVAL_MS)
        } else {
            pendingMessageId = null
            pendingSender = null
            pendingSubject = null
            Toast.makeText(this, R.string.email_not_found, Toast.LENGTH_SHORT).show()
        }
    }

    private fun setupTabs() {
        keywordChips.setOnCheckedStateChangeListener { group, checkedIds ->
            val checkedId = checkedIds.firstOrNull() ?: return@setOnCheckedStateChangeListener
            selectedTab = (group.findViewById<Chip>(checkedId))?.text?.toString().orEmpty().ifBlank { KeywordTabs.ALL }
            renderFilteredEmails()
        }

        rebuildTabs(emptyList())
    }

    private fun styleKeywordChip(chip: Chip) = applyPillChipTheme(this, chip)

    private fun scheduleNextRefresh() {
        mainHandler.removeCallbacks(refreshRunnable)
        // ponytail: foreground best-effort cadence; upgrade path is server push + work resumption.
        mainHandler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS)
    }

    /**
     * [forceFullResync] is the difference between the 90-second cadence and a user pulling down.
     *
     * The automatic path sends the persisted cursor, so the relay answers with a delta — which is
     * right for a background poll and wrong for someone who just told the app they think it is out of
     * date. A delta cannot repair a cache that has drifted: `reconcileFetchResult` merges "updated"
     * entries over the existing row and skips entries it has never seen, so the states a user
     * actually pulls down about survive it. `since=0` re-reads the folder and prunes what is gone.
     *
     * There is already a daily forced resync for the same reason (`MailCursorStore`). A push tap
     * also forces one: opening its cached match would freeze stale body/bodyMode in the detail view.
     */
    private fun refreshInbox(forceFullResync: Boolean = pendingMessageId != null) {
        // No emails held in memory yet (cold open, or a just-switched-to folder) — render the
        // Room cache immediately so the list isn't empty while the network round trip is in
        // flight, then let the fetch below overwrite it with fresh data.
        //
        // Never on a pull: the gesture has its own spinner, and raising the full-screen overlay over
        // it would replace the list the user is looking at.
        val showCacheFirst = (allEmails.isEmpty() || pendingMessageId != null) && !forceFullResync
        if (showCacheFirst) {
            loadingOverlay.visibility = android.view.View.VISIBLE
            val status = if (pendingMessageId != null) {
                val detail = if (!pendingSender.isNullOrBlank()) " from $pendingSender" else ""
                getString(R.string.finding_email) + detail
            } else {
                getString(R.string.loading_emails)
            }
            loadingStatus.text = status
            cancelLoading.visibility = if (pendingMessageId != null) View.VISIBLE else View.GONE
        }
        ioExecutor.execute {
            // try/finally, not a call at the end of the happy path. cachedEmails and
            // rememberKeywords both touch Room and can throw, and a spinner that never stops is a
            // screen the user has to back out of to escape.
            try {
                refreshInboxOnIo(showCacheFirst, forceFullResync)
            } finally {
                runOnUiThread { swipeRefresh.isRefreshing = false }
            }
        }
    }

    private fun refreshInboxOnIo(showCacheFirst: Boolean, forceFullResync: Boolean) {
        if (showCacheFirst) {
            val cached = mailRepository.cachedEmails(currentFolder)
            if (cached.isNotEmpty()) {
                runOnUiThread {
                    allEmails = cached
                    rebuildTabs(cached)
                    renderFilteredEmails()
                    checkPendingMessage(cached, isFinal = false)
                    // If we aren't waiting for a specific message (it was found in cache or 
                    // this isn't a deep link), we can hide the overlay now.
                    if (pendingMessageId == null) {
                        loadingOverlay.visibility = android.view.View.GONE
                    }
                }
            }
        }
        val outcome: MailOutcome<MailFetchResult> =
            mailRepository.refreshFolder(currentFolder, forceFullResync = forceFullResync)
        val emails = mailRepository.cachedEmails(currentFolder)
        val errorMessage = outcome.userFacingMessage()
        keywordSettings.rememberKeywords(emails.flatMap { it.keywords }.toSet())
        runOnUiThread {
            loadingOverlay.visibility = android.view.View.GONE
            allEmails = emails
            rebuildTabs(emails)
            renderFilteredEmails()
            checkPendingMessage(emails, isFinal = true)
            if (errorMessage != null) {
                Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun rebuildTabs(emails: List<Email>) {
        // Always show every allowed (visible-in-Keyword-Settings) keyword the app has ever seen,
        // not just ones present in the current email batch — a keyword tab shouldn't disappear
        // just because its last matching email got archived/deleted/filtered to another folder.
        val discoveredThisBatch = KeywordTabs.buildTabs(emails).drop(1).toSet()
        keywordSettings.rememberKeywords(discoveredThisBatch)
        val allowedKeywords = keywordSettings.filterVisible(keywordSettings.getAllKeywords()).sortedBy { it.lowercase() }
        val tabs = listOf(KeywordTabs.ALL) + allowedKeywords

        val current = mutableListOf<String>()
        for (index in 0 until keywordChips.childCount) {
            current.add((keywordChips.getChildAt(index) as? Chip)?.text?.toString().orEmpty())
        }
        if (tabs != current) {
            keywordChips.removeAllViews()
            if (!tabs.contains(selectedTab)) {
                selectedTab = KeywordTabs.ALL
            }
            tabs.forEach { keyword ->
                val chip = Chip(this).apply {
                    text = keyword
                    isCheckable = true
                    isClickable = true
                    isChecked = keyword == selectedTab
                }
                styleKeywordChip(chip)
                keywordChips.addView(chip)
            }
        }

        // Unread state (bold text + a small leading accent dot, matching the same cue used on
        // inbox rows in EmailAdapter) tracks unread counts, which can change on a refresh even
        // when the keyword set itself doesn't, so refresh it unconditionally rather than folding
        // it into the rebuild check above.
        val dotSizePx = (7 * resources.displayMetrics.density).toInt()
        for (index in 0 until keywordChips.childCount) {
            val chip = keywordChips.getChildAt(index) as? Chip ?: continue
            val keyword = chip.text.toString()
            val hasUnread = emails.any {
                it.status == "unread" && (keyword == KeywordTabs.ALL || it.keywords.contains(keyword))
            }
            chip.setTypeface(chip.typeface, if (hasUnread) Typeface.BOLD else Typeface.NORMAL)
            chip.isChipIconVisible = hasUnread
            if (hasUnread) {
                chip.chipIconSize = dotSizePx.toFloat()
                chip.chipIcon = unreadDotDrawable(this, sizeDp = 7)
                // A checked chip is already accent-filled, so an accent-colored dot would
                // disappear into it — use the chip's own (contrasting) text color instead. This
                // has to be a ColorStateList (like chipBackgroundColor/chipStrokeColor already
                // are), not a one-off flat color: tapping a chip only toggles its checked state,
                // it doesn't re-run this loop, so a flat color baked in at whatever checked state
                // happened to be current here goes stale the moment the user selects a different
                // pill — which is exactly what showed as a dot stuck black in dark themes.
                val accent = Color.parseColor(getStoredThemePalette(this).accent)
                val onAccent = readableOn(accent)
                val checkedState = intArrayOf(android.R.attr.state_checked)
                val uncheckedState = intArrayOf(-android.R.attr.state_checked)
                chip.chipIconTint = ColorStateList(arrayOf(checkedState, uncheckedState), intArrayOf(onAccent, accent))
            } else {
                chip.chipIcon = null
            }
        }
    }

    private fun renderFilteredEmails() {
        val filtered = KeywordTabs.filterEmails(allEmails, selectedTab)
        adapter.updateEmails(filtered)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        if (redirectedToUnlock) return false
        menu?.add(0, MENU_PGP_KEY, 0, R.string.menu_pgp_key)
        menu?.add(0, MENU_KEYWORDS, 1, R.string.menu_keywords)
        menu?.add(0, MENU_THEMES, 2, R.string.menu_themes)
        menu?.add(0, MENU_PUSH_PAIRING, 3, R.string.menu_pairing)
        menu?.add(0, MENU_SECURITY, 4, R.string.menu_security)
        menu?.add(0, MENU_ABOUT, 5, R.string.menu_about)
        return super.onCreateOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_PGP_KEY -> {
                startActivity(Intent(this, PgpKeyActivity::class.java))
                true
            }
            MENU_KEYWORDS -> {
                startActivity(Intent(this, KeywordSettingsActivity::class.java))
                true
            }
            MENU_THEMES -> {
                startActivity(Intent(this, ThemesActivity::class.java))
                true
            }
            MENU_PUSH_PAIRING -> {
                startActivity(Intent(this, com.urlxl.mail.push.PushPairingActivity::class.java))
                true
            }
            MENU_SECURITY -> {
                startActivity(Intent(this, com.urlxl.mail.security.SecuritySettingsActivity::class.java))
                true
            }
            MENU_ABOUT -> {
                showAboutDialog(this)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun switchFolder(folder: String) {
        currentFolder = folder
        selectedTab = KeywordTabs.ALL
        applyFolderTitle()
        refreshInbox()
    }

    private fun showFolderPickerPopup(anchor: View) {
        val popupMenu = PopupMenu(this, anchor)
        popupMenu.menu.add(0, 0, 0, getString(R.string.nav_inbox))
        popupMenu.menu.add(0, 1, 1, getString(R.string.nav_junk))
        popupMenu.menu.add(0, 2, 2, getString(R.string.nav_trash))
        popupMenu.menu.add(0, 3, 3, getString(R.string.nav_archive))

        popupMenu.setOnMenuItemClickListener { menuItem ->
            val folder = when (menuItem.itemId) {
                0 -> "INBOX"
                1 -> "Junk"
                2 -> "Trash"
                3 -> {
                    fetchAndShowArchiveSubfolders(anchor)
                    return@setOnMenuItemClickListener true
                }
                else -> return@setOnMenuItemClickListener false
            }
            switchFolder(folder)
            true
        }
        popupMenu.show()
    }

    private fun fetchAndShowArchiveSubfolders(anchor: View) {
        ioExecutor.execute {
            val outcome = mailRepository.listFolders(ARCHIVE_PARENT_FOLDER)
            runOnUiThread {
                if (outcome is MailOutcome.Success) {
                    showArchiveSubfoldersPopup(anchor, outcome.value.folders)
                } else {
                    val errorMessage = outcome.userFacingMessage()
                    if (errorMessage != null) {
                        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun showArchiveSubfoldersPopup(anchor: View, folders: List<FolderInfo>) {
        if (folders.isEmpty()) {
            Toast.makeText(this, R.string.no_archive_folders, Toast.LENGTH_SHORT).show()
            return
        }
        val popupMenu = PopupMenu(this, anchor)
        folders.forEachIndexed { index, folder ->
            popupMenu.menu.add(0, index, index, folder.path.substringAfterLast('/'))
        }
        popupMenu.setOnMenuItemClickListener { menuItem ->
            val folder = folders.getOrNull(menuItem.itemId) ?: return@setOnMenuItemClickListener false
            switchFolder(folder.path)
            true
        }
        popupMenu.show()
    }

    private fun setupBottomNav() {
        fun openFolderPickerFromTab() {
            val anchor = bottomNav.findViewById<View>(R.id.nav_inbox) ?: bottomNav
            showFolderPickerPopup(anchor)
        }

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_inbox -> {
                    if (!suppressFolderPickerReentry) {
                        openFolderPickerFromTab()
                    }
                    true
                }
                // Return false for items that launch a separate screen: the tap still fires the
                // action, but the nav selection stays on Inbox. Returning true would mark the item
                // selected, and BottomNavigationView never re-fires the selected listener for an
                // already-selected item — making the button dead after returning via back.
                R.id.nav_compose -> {
                    startActivity(Intent(this, ComposeActivity::class.java))
                    false
                }
                R.id.nav_contacts -> {
                    startActivity(Intent(this, com.urlxl.mail.contacts.ContactsListActivity::class.java))
                    false
                }
                else -> false
            }
        }
        bottomNav.setOnItemReselectedListener { item ->
            if (item.itemId == R.id.nav_inbox && !suppressFolderPickerReentry) {
                openFolderPickerFromTab()
            }
        }
        suppressFolderPickerReentry = true
        try {
            bottomNav.selectedItemId = R.id.nav_inbox
        } finally {
            suppressFolderPickerReentry = false
        }
    }

    private fun setupSwipeGestures() {
        val iconSize = (24 * resources.displayMetrics.density).toInt()
        val iconMargin = (16 * resources.displayMetrics.density).toInt()
        val archiveIcon = ContextCompat.getDrawable(this, R.drawable.ic_archive)?.mutate()?.apply {
            setTint(readableOn(SWIPE_ARCHIVE_COLOR))
        }
        val deleteIcon = ContextCompat.getDrawable(this, R.drawable.ic_delete)?.mutate()?.apply {
            setTint(readableOn(SWIPE_DELETE_COLOR))
        }
        // Rounded on the same side as the row's own corners (item_email.xml's 14dp
        // cardCornerRadius) so the reveal doesn't show a sharp corner poking out from behind the
        // rounded card as it slides away.
        val cardRadius = resources.getDimension(R.dimen.card_corner_radius)
        val deleteBackground = android.graphics.drawable.GradientDrawable().apply {
            setColor(SWIPE_DELETE_COLOR)
            cornerRadii = floatArrayOf(cardRadius, cardRadius, 0f, 0f, 0f, 0f, cardRadius, cardRadius)
        }
        val archiveBackground = android.graphics.drawable.GradientDrawable().apply {
            setColor(SWIPE_ARCHIVE_COLOR)
            cornerRadii = floatArrayOf(0f, 0f, cardRadius, cardRadius, cardRadius, cardRadius, 0f, 0f)
        }

        val itemTouchHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            0,
            ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean = false

            override fun onChildDraw(
                c: Canvas,
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                dX: Float,
                dY: Float,
                actionState: Int,
                isCurrentlyActive: Boolean
            ) {
                if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE) {
                    val itemView = viewHolder.itemView
                    val iconTop = itemView.top + (itemView.height - iconSize) / 2
                    val iconBottom = iconTop + iconSize

                    when {
                        dX > 0 -> {
                            deleteBackground.setBounds(
                                itemView.left, itemView.top, itemView.left + dX.toInt(), itemView.bottom
                            )
                            deleteBackground.draw(c)
                            if (dX > iconSize + iconMargin * 2) {
                                val iconLeft = itemView.left + iconMargin
                                deleteIcon?.setBounds(iconLeft, iconTop, iconLeft + iconSize, iconBottom)
                                deleteIcon?.draw(c)
                            }
                        }
                        dX < 0 -> {
                            archiveBackground.setBounds(
                                itemView.right + dX.toInt(), itemView.top, itemView.right, itemView.bottom
                            )
                            archiveBackground.draw(c)
                            if (-dX > iconSize + iconMargin * 2) {
                                val iconRight = itemView.right - iconMargin
                                archiveIcon?.setBounds(iconRight - iconSize, iconTop, iconRight, iconBottom)
                                archiveIcon?.draw(c)
                            }
                        }
                    }
                }
                super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive)
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                if (position < 0 || position >= adapter.itemCount) return
                val email = adapter.getEmailAt(position)
                // Remove the row immediately and let the IMAP call finish on its own; waiting for
                // the network round trip before updating the list is what made swipes feel slow.
                when (direction) {
                    ItemTouchHelper.LEFT -> {
                        allEmails = allEmails.filter { it.id != email.id }
                        renderFilteredEmails()
                        MailBackgroundExecutor.submitReporting(
                            this@InboxActivity,
                            getString(R.string.action_archive),
                        ) { mailRepository.archive(email.id, currentFolder) }
                    }
                    ItemTouchHelper.RIGHT -> {
                        allEmails = allEmails.filter { it.id != email.id }
                        renderFilteredEmails()
                        MailBackgroundExecutor.submitReporting(
                            this@InboxActivity,
                            getString(R.string.action_delete),
                        ) { mailRepository.delete(email.id, currentFolder) }
                    }
                }
            }
        })
        itemTouchHelper.attachToRecyclerView(recyclerView)
    }

    companion object {
        private const val REFRESH_INTERVAL_MS = 90_000L
        private const val PENDING_MESSAGE_POLL_INTERVAL_MS = 3_000L
        private const val PENDING_MESSAGE_TIMEOUT_MS = 30_000L
        private const val ARCHIVE_PARENT_FOLDER = "Archive"
        private const val MENU_PGP_KEY = 0
        private const val MENU_KEYWORDS = 1
        private const val MENU_THEMES = 2
        private const val MENU_PUSH_PAIRING = 3
        private const val MENU_SECURITY = 4
        private const val MENU_ABOUT = 5
        private val SWIPE_ARCHIVE_COLOR = Color.parseColor(COLOR_WARNING)
        private val SWIPE_DELETE_COLOR = Color.parseColor(COLOR_DANGER)
    }
}
