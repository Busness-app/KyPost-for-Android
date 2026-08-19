package org.kysecurity.mail

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.mail.FolderInfo
import org.kysecurity.mail.mail.MailFetchResult
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.isFlaggedPhishing
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.push.PushNotificationDispatcher
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.kysecurity.mail.security.LockedActivity

class InboxActivity : LockedActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var keywordChipScroll: View
    private lateinit var keywordChips: ChipGroup
    private lateinit var bottomNav: NavigationBarView
    private lateinit var loadingOverlay: View
    private lateinit var swipeRefresh: androidx.swiperefreshlayout.widget.SwipeRefreshLayout
    private lateinit var loadingStatus: TextView
    private lateinit var cancelLoading: View
    private lateinit var inboxRoot: View
    private lateinit var inboxContent: View
    private lateinit var adapter: EmailAdapter
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var mailRepository: MailRepository
    private lateinit var keywordSettings: KeywordSettings
    private var currentFolder = "INBOX"
    private var lastAppliedThemeName: String = ""
    private var pendingScrollPosition: Int = 0

    private var selectedTab = KeywordTabs.ALL
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

    // The backend can take seconds to index a just-pushed email, so poll instead of a single try.
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

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        savedInstanceState?.let { state ->
            currentFolder = state.getString(STATE_FOLDER, currentFolder)
            selectedTab = state.getString(STATE_TAB, selectedTab)
            pendingScrollPosition = state.getInt(STATE_SCROLL, 0)
        }
        setContentView(R.layout.activity_inbox)
        applyThemeToActivity(this)
        lastAppliedThemeName = getStoredThemeName(this)

        mailRepository = MailRuntime.graph(this).repository
        keywordSettings = KeywordSettings(this)

        initViews()
        applyFolderTitle()
        applyTopInsetWithHeader(this, inboxContent)
        applyPrimaryNavigationInsets(this, bottomNav)
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
        val folderLabel = currentFolderLabel()
        val title = getString(R.string.inbox_heading, folderLabel)
        setTitle(title)
        applyKyPostTopBar(this, folderLabel)
        if (::bottomNav.isInitialized) {
            bottomNav.menu.findItem(R.id.nav_inbox)?.title = folderLabel
        }
    }

    private fun currentFolderLabel(): String {
        return when {
            currentFolder == "Junk" -> getString(R.string.nav_junk)
            currentFolder == "Trash" -> getString(R.string.nav_trash)
            currentFolder == ARCHIVE_PARENT_FOLDER -> getString(R.string.nav_archive)
            currentFolder.startsWith("$ARCHIVE_PARENT_FOLDER/") -> currentFolder.substringAfterLast('/')
            else -> getString(R.string.nav_inbox)
        }
    }

    override fun onStartUnlocked() {
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

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // Identifiers and positions only. No subjects, senders or bodies: this Bundle is
        // system-managed storage outside the app's control.
        outState.putString(STATE_FOLDER, currentFolder)
        outState.putString(STATE_TAB, selectedTab)
        // A still-unconsumed pending target wins: the list is empty until the folder has loaded.
        val layoutManager = recyclerView.layoutManager as? LinearLayoutManager
        val visible = layoutManager?.findFirstVisibleItemPosition() ?: 0
        outState.putInt(STATE_SCROLL, if (pendingScrollPosition > 0) pendingScrollPosition else visible)
    }

    private fun initViews() {
        inboxRoot = findViewById(R.id.inboxRoot)
        inboxContent = findViewById(R.id.inboxContent)
        recyclerView = findViewById(R.id.recyclerViewInbox)
        keywordChipScroll = findViewById(R.id.keywordChipScroll)
        keywordChips = findViewById(R.id.keywordChipGroup)
        bottomNav = findViewById(R.id.bottomNavigation)
        loadingOverlay = findViewById(R.id.loadingOverlay)
        swipeRefresh = findViewById(R.id.inboxSwipeRefresh)
        // forceFullResync: a delta cannot repair a drifted cache, so a pull re-reads the folder.
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

        inboxRoot.setBackgroundColor(bg)
        inboxContent.setBackgroundColor(bg)
        recyclerView.setBackgroundColor(bg)

        applyFolderTitle()

        // Rounded panel bar behind the keyword pills — shared STYLE_GUIDE.md §3 Card/panel radius.
        applyPanelBackground(this, keywordChipScroll)

        // Re-style every existing chip in place so a theme switch recolors them even when
        // rebuildTabs() short-circuits because the keyword set itself hasn't changed.
        for (index in 0 until keywordChips.childCount) {
            (keywordChips.getChildAt(index) as? Chip)?.let { styleKeywordChip(it) }
        }

        applyPrimaryNavigationTheme(this, bottomNav)
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
        // Signature state is what separates an authentic signed message from an impersonation.
        intent.putExtra("email_pgp_signed", email.pgpSigned)
        intent.putExtra("email_pgp_verified", email.pgpVerified)
        intent.putExtra("email_pgp_signer_fingerprint", email.pgpSignerFingerprint)
        // The server's $Phishing IMAP keyword; see mail/PhishingFlag.kt for the case-insensitive match.
        intent.putExtra("email_suspicious", isFlaggedPhishing(email.keywords))
        emailDetailLauncher.launch(intent)
    }

    private fun checkPendingMessage(emails: List<Email>, isFinal: Boolean = false) {
        val id = pendingMessageId ?: return
        
        // Fuzzy fallback for IMAP id mismatches. Needs a non-blank sender: contains("") matches anything.
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
            // Still inside the deep-link wait window: the backend may not have indexed it yet.
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

    /** [forceFullResync] sends `since=0`: a delta cannot repair a cache that has drifted. */
    private fun refreshInbox(forceFullResync: Boolean = pendingMessageId != null) {
        // Render the Room cache first on a cold open; never on a pull, which has its own spinner.
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
            // try/finally: cachedEmails and rememberKeywords both touch Room and can throw.
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
        // Show every remembered keyword, not just this batch's: a tab must not vanish when mail moves.
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

        // Unread counts change on a refresh even when the keyword set does not, so refresh always.
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
                // ColorStateList, not a flat color: toggling checked never re-runs this loop.
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
        if (pendingScrollPosition > 0 && adapter.itemCount > 0) {
            val target = pendingScrollPosition.coerceAtMost(adapter.itemCount - 1)
            pendingScrollPosition = 0
            recyclerView.scrollToPosition(target)
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
        popupMenu.menu.add(0, 0, 0, getString(R.string.nav_inbox)).isChecked = currentFolder == "INBOX"
        popupMenu.menu.add(0, 1, 1, getString(R.string.nav_junk)).isChecked = currentFolder == "Junk"
        popupMenu.menu.add(0, 2, 2, getString(R.string.nav_trash)).isChecked = currentFolder == "Trash"
        popupMenu.menu.add(0, 3, 3, getString(R.string.nav_archive)).isChecked =
            currentFolder == ARCHIVE_PARENT_FOLDER || currentFolder.startsWith("$ARCHIVE_PARENT_FOLDER/")
        popupMenu.menu.setGroupCheckable(0, true, true)

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
            popupMenu.menu.add(0, index, index, folder.path.substringAfterLast('/')).isChecked =
                currentFolder == folder.path
        }
        popupMenu.menu.setGroupCheckable(0, true, true)
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

        setupPrimaryNavigation(this, bottomNav, R.id.nav_inbox, ::openFolderPickerFromTab)
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
        // Rounded on the row's own corners so no sharp corner pokes out from behind the card.
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
                val position = viewHolder.bindingAdapterPosition
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

    @androidx.annotation.VisibleForTesting
    internal fun setFolderForTest(folder: String, tab: String) {
        currentFolder = folder
        selectedTab = tab
        if (::bottomNav.isInitialized) {
            applyFolderTitle()
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun currentFolderForTest(): String = currentFolder

    @androidx.annotation.VisibleForTesting
    internal fun selectedTabForTest(): String = selectedTab

    @androidx.annotation.VisibleForTesting
    internal fun setPendingScrollPositionForTest(position: Int) {
        pendingScrollPosition = position
    }

    @androidx.annotation.VisibleForTesting
    internal fun pendingScrollPositionForTest(): Int = pendingScrollPosition

    companion object {
        private const val REFRESH_INTERVAL_MS = 90_000L
        private const val PENDING_MESSAGE_POLL_INTERVAL_MS = 3_000L
        private const val PENDING_MESSAGE_TIMEOUT_MS = 30_000L
        private const val ARCHIVE_PARENT_FOLDER = "Archive"
        const val STATE_FOLDER = "inbox_folder"
        const val STATE_TAB = "inbox_tab"
        const val STATE_SCROLL = "inbox_scroll"
        private val SWIPE_ARCHIVE_COLOR = Color.parseColor(COLOR_WARNING)
        private val SWIPE_DELETE_COLOR = Color.parseColor(COLOR_DANGER)
    }
}
