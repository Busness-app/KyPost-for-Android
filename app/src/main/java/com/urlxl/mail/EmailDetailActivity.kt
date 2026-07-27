package com.urlxl.mail

import android.content.ContentValues
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.text.TextUtils
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.urlxl.mail.mail.AttachmentInfo
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.MailRepository
import com.urlxl.mail.mail.MailRuntime
import com.urlxl.mail.mail.addressFromHeader
import com.urlxl.mail.mail.userFacingMessage
import com.urlxl.mail.pgp.PgpMessageState
import com.urlxl.mail.pgp.pgpMessageStateOf
import com.urlxl.mail.pgp.webmailMessageUrl
import com.urlxl.mail.push.PushRuntime
import java.util.concurrent.Executors
import com.urlxl.mail.security.LockedActivity

class EmailDetailActivity : LockedActivity() {

    private val ioExecutor = Executors.newSingleThreadExecutor()
    private lateinit var mailRepository: MailRepository
    private lateinit var actionButtons: List<ImageButton>
    private lateinit var divider: View
    private lateinit var webView: WebView
    private lateinit var imagesBlockedBar: View
    private lateinit var btnShowImages: Button
    private lateinit var phishingBar: TextView
    private lateinit var pgpBar: View
    private lateinit var pgpText: TextView
    private lateinit var btnOpenInWebmail: Button
    private var lastAppliedThemeName: String = ""
    private var lastRenderedHtml: String? = null

    /** The message's real body, once the background fetch has answered. Reply/Forward quote this;
     *  see [quoteForReply] for why the 140-character preview was never an acceptable substitute. */
    private var fetchedBodyHtml: String? = null

    /** Attachments downloaded on this screen, keyed by their listing index, so Forward can carry
     *  them. Populated lazily — only what the user actually opened is here, which is the honest
     *  limit of what this screen has without re-fetching every attachment on entry. */
    private val downloadedAttachments = linkedMapOf<Int, com.urlxl.mail.mail.OutgoingAttachment>()

    /** This message's attachment listing, once loaded — what Forward has to fetch. */
    private var attachmentInfos: List<AttachmentInfo> = emptyList()

    private var toRecipients: List<String> = emptyList()
    private var ccRecipients: List<String> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return
        setContentView(R.layout.activity_email_detail)
        applyThemeToActivity(this)
        lastAppliedThemeName = getStoredThemeName(this)

        val root = findViewById<android.view.View>(R.id.emailDetailRoot)
        applyTopInsetWithHeader(this, root)

        val emailId = intent.getStringExtra("email_id").orEmpty()
        val emailFolder = intent.getStringExtra("email_folder") ?: "INBOX"
        val emailSubject = intent.getStringExtra("email_subject") ?: "No subject"
        val emailSender = intent.getStringExtra("email_sender") ?: "Unknown sender"
        val emailPreview = intent.getStringExtra("email_preview") ?: "No content"
        val hasAttachments = intent.getBooleanExtra("email_has_attachments", false)
        val pgpEncrypted = intent.getBooleanExtra("email_pgp_encrypted", false)
        val pgpDecryptError = intent.getStringExtra("email_pgp_decrypt_error").orEmpty()
        val phishingFlagged = intent.getBooleanExtra("email_suspicious", false)

        setTitle(R.string.email_title)

        val subjectView = findViewById<TextView>(R.id.emailSubject)
        val fromView = findViewById<TextView>(R.id.emailFrom)
        webView = findViewById(R.id.emailWebView)
        divider = findViewById(R.id.emailDivider)
        imagesBlockedBar = findViewById(R.id.emailImagesBlockedBar)
        btnShowImages = findViewById(R.id.btnShowImages)
        phishingBar = findViewById(R.id.emailPhishingBar)
        // Advisory only: the links this warns about are already refused by
        // SAFE_LINK_SCHEMES in shouldOverrideUrlLoading, whether or not the
        // server ever flagged the message.
        phishingBar.visibility = if (phishingFlagged) View.VISIBLE else View.GONE
        pgpBar = findViewById(R.id.emailPgpBar)
        pgpText = findViewById(R.id.emailPgpText)
        btnOpenInWebmail = findViewById(R.id.btnOpenInWebmail)
        val loading = findViewById<ProgressBar>(R.id.emailBodyLoading)

        subjectView.text = emailSubject
        fromView.text = getString(R.string.email_from) + " " + emailSender

        mailRepository = MailRuntime.graph(this).repository

        val actionArchive = findViewById<ImageButton>(R.id.actionArchive)
        val actionJunk = findViewById<ImageButton>(R.id.actionJunk)
        val actionDelete = findViewById<ImageButton>(R.id.actionDelete)
        val actionReply = findViewById<ImageButton>(R.id.actionReply)
        val actionReplyAll = findViewById<ImageButton>(R.id.actionReplyAll)
        val actionForward = findViewById<ImageButton>(R.id.actionForward)
        actionButtons = listOf(
            actionReply, actionReplyAll, actionForward,
            actionArchive, actionJunk, actionDelete,
        )
        applyDetailChrome()

        // markRead stays non-reporting on purpose: it is incidental to opening the message, and a
        // toast about it would fire on top of the message the user just opened.
        MailBackgroundExecutor.submit { mailRepository.markRead(emailId, emailFolder) }

        actionArchive.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_archive), emailId) { it.archive(emailId, emailFolder) }
        }
        actionDelete.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_delete), emailId) { it.delete(emailId, emailFolder) }
        }
        actionJunk.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_junk), emailId) { it.spam(emailId, emailFolder) }
        }
        actionReply.setOnClickListener {
            openCompose(
                to = extractAddress(emailSender),
                subject = withPrefix(emailSubject, "Re:"),
                bodyHtml = quoteForReply(emailSender, emailPreview),
            )
        }
        actionReplyAll.setOnClickListener {
            val recipients = (listOf(extractAddress(emailSender)) + toRecipients.map(::extractAddress) + ccRecipients.map(::extractAddress))
                .distinct()
                .filter { it.isNotBlank() }
            openCompose(
                to = recipients.joinToString(", "),
                subject = withPrefix(emailSubject, "Re:"),
                bodyHtml = quoteForReply(emailSender, emailPreview),
            )
        }
        actionForward.setOnClickListener {
            forwardMessage(emailId, emailFolder, emailSender, emailSubject, emailPreview)
        }

        if (hasAttachments) {
            loadAttachments(emailId, emailFolder)
        }

        webView.settings.apply {
            javaScriptEnabled = false
            builtInZoomControls = true
            displayZoomControls = false
            useWideViewPort = true
            loadWithOverviewMode = true
            defaultTextEncodingName = "utf-8"
            // Defaults that are wrong for a renderer whose input is attacker-controlled HTML:
            // allowContentAccess defaults to true, which lets email markup reference this app's
            // own content:// providers, and DOM storage is state an email has no business
            // creating. allowFileAccess is already false on this minSdk but is pinned here so it
            // stays false if the default ever moves.
            allowContentAccess = false
            allowFileAccess = false
            domStorageEnabled = false
            // Senders can embed tracking beacons — not just <img>, but <iframe>, <video>/<audio>
            // src or poster, <link rel="stylesheet">, and remote web fonts all fetch over the
            // network too, and blockNetworkImage only covers image-typed resources. Blocking all
            // network loads closes those too; loading them automatically would leak the reader's
            // IP and "message opened" status before they've decided whether to trust the sender.
            // btnShowImages lets them opt in per-message instead.
            blockNetworkLoads = true
        }
        // Without a WebViewClient, WebView handles navigation itself: tapping a link in an email —
        // or a <meta http-equiv="refresh"> the sender planted — replaced this view's contents with
        // the target page, in-app, with no address bar for the user to check. That is a ready-made
        // phishing surface inside a trusted mail client. Hand every navigation to the system
        // instead, so it opens in a real browser with a visible URL.
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                // Only act on a real tap. Sender HTML navigates on its own — an <iframe src> or a
                // <meta http-equiv="refresh"> fires this callback with hasGesture() false, needing
                // no JavaScript and no user interaction beyond opening the message. blockNetworkLoads
                // does not help: it gates resource loads, while this is a navigation throttle that
                // runs first, so a non-http scheme sails straight past it. Un-gestured, that gave a
                // remote sender one free implicit ACTION_VIEW per opened mail to any scheme on the
                // device — including this app's own kypost://native-pair, which conjures the pairing
                // dialog on top of the attacker's own pretext.
                if (!request.hasGesture()) return true
                val scheme = request.url.scheme?.lowercase()
                if (scheme !in SAFE_LINK_SCHEMES) {
                    Toast.makeText(
                        this@EmailDetailActivity,
                        R.string.email_link_blocked_scheme,
                        Toast.LENGTH_SHORT,
                    ).show()
                    return true
                }
                openExternally(request.url)
                return true
            }
        }
        btnShowImages.setOnClickListener {
            webView.settings.blockNetworkLoads = false
            imagesBlockedBar.visibility = View.GONE
            // WebView.reload() doesn't reliably re-fetch a page loaded via loadDataWithBaseURL, so
            // re-issue the same load now that the setting allows network images through.
            lastRenderedHtml?.let { html -> webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null) }
        }

        // runCatching, not a bare block: an uncaught exception on an ExecutorService thread is a
        // process kill, and every input below is chosen by the sender — the body HTML, its length,
        // its CSS. `stripImportant` threw on a six-hex-digit CSS escape above the Unicode codespace
        // (fixed in decodeCssEscapes), which crashed the app on open and again on every reopen,
        // since the message stays in the mailbox. The decode bug is fixed; this makes the next one
        // an unreadable message rather than an unusable app.
        ioExecutor.execute {
            runCatching { renderBody(emailId, emailFolder, emailPreview, pgpEncrypted, pgpDecryptError, loading) }
                .onFailure { error ->
                    android.util.Log.e(TAG, "Failed to render message body", error)
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        loading.visibility = android.view.View.GONE
                        Toast.makeText(this, R.string.email_body_render_failed, Toast.LENGTH_LONG).show()
                    }
                }
        }
    }

    /** The body fetch, PGP-state resolution and HTML assembly for one message. Extracted from
     *  `onCreate` so the whole thing sits inside one `runCatching` on the executor thread — see the
     *  call site for why that matters. */
    private fun renderBody(
        emailId: String,
        emailFolder: String,
        emailPreview: String,
        pgpEncrypted: Boolean,
        pgpDecryptError: String,
        loading: ProgressBar,
    ) {
        val outcome = mailRepository.fetchBody(emailId, emailFolder)
        val content = (outcome as? MailOutcome.Success)?.value
        // A failed fetch means "not cached", which is NOT the same as "the server sent no
        // body" — see MailRepository.fetchBody.
        val bodyUnavailable = outcome !is MailOutcome.Success
        val pgpState = pgpMessageStateOf(pgpEncrypted, pgpDecryptError, content?.html, bodyUnavailable)
        // A client-protected message has no body to fall back to, and emailPreview is the
        // placeholder subject line — rendering it would look like the message content.
        val bodyToRender = when (pgpState) {
            PgpMessageState.CLIENT_PROTECTED,
            PgpMessageState.DECRYPT_FAILED,
            PgpMessageState.BODY_UNAVAILABLE -> ""
            else -> content?.html?.takeIf { it.isNotBlank() } ?: TextUtils.htmlEncode(emailPreview)
        }
        // Same length cap as stripImportant, for the same reason: this is a cosmetic heuristic,
        // and on a multi-megabyte sender-chosen body a bounded "assume none" beats an unbounded
        // scan. Belt-and-braces with the bounded tag interior in the pattern itself.
        val hasRemoteImages = bodyToRender.length <= STRIP_IMPORTANT_MAX_LENGTH &&
            REMOTE_IMAGE_PATTERN.containsMatchIn(bodyToRender)
        val palette = getStoredThemePalette(this)
        val monoFontFace = ibmPlexMonoFontFaceCss(this)

        val htmlContent = buildEmailBodyHtml(bodyToRender, palette, monoFontFace, isDark = isDarkPalette(palette))
        // Resolved here rather than in renderPgpBar: pairingForAuthenticatedCall reads the
        // Keystore-backed EncryptedSharedPreferences, which is disk I/O and does not belong
        // on the main thread. Only needed for the one state that offers the button.
        val webmailUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
            PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
                ?.let { webmailMessageUrl(it, emailFolder, emailId) }
        } else {
            null
        }

        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            lastRenderedHtml = htmlContent
            // Not `bodyToRender`: that is blanked for the PGP states with nothing to show.
            fetchedBodyHtml = content?.html
            webView.loadDataWithBaseURL(null, htmlContent, "text/html", "utf-8", null)
            loading.visibility = android.view.View.GONE
            imagesBlockedBar.visibility = if (hasRemoteImages) View.VISIBLE else View.GONE
            renderPgpBar(pgpState, pgpDecryptError, webmailUrl)
            if (content != null) {
                toRecipients = content.toAddresses
                ccRecipients = content.ccAddresses
            }
        }
    }

    /**
     * Opens the composer with the whole message: the real body, and every attachment.
     *
     * Forward used to send `emailPreview` — 140 characters of the sender's raw HTML — with no
     * attachments at all, which meant the feature did not forward the message in any meaningful
     * sense. Anything not already downloaded for this screen is fetched here first, because a
     * forward without its attachments is a silent data-loss bug the user only discovers when the
     * recipient asks where the file is.
     */
    private fun forwardMessage(
        emailId: String,
        emailFolder: String,
        emailSender: String,
        emailSubject: String,
        emailPreview: String,
    ) {
        val missing = attachmentInfos.filter { it.index !in downloadedAttachments }
        if (missing.isEmpty()) {
            openCompose(
                to = "",
                subject = withPrefix(emailSubject, "Fwd:"),
                bodyHtml = quoteForForward(emailSender, emailSubject, emailPreview),
                attachments = orderedForwardAttachments(),
            )
            return
        }

        Toast.makeText(this, R.string.forward_fetching_attachments, Toast.LENGTH_SHORT).show()
        ioExecutor.execute {
            val fetched = missing.map { info ->
                info.index to (mailRepository.downloadAttachment(emailId, emailFolder, info.index) as? MailOutcome.Success)?.value
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                fetched.forEach { (index, downloaded) ->
                    if (downloaded != null) rememberForForwarding(index, downloaded)
                }
                val failed = fetched.count { it.second == null }
                if (failed > 0) {
                    // Say so rather than quietly forwarding a message with attachments missing.
                    Toast.makeText(
                        this,
                        getString(R.string.forward_attachments_failed, failed),
                        Toast.LENGTH_LONG,
                    ).show()
                }
                openCompose(
                    to = "",
                    subject = withPrefix(emailSubject, "Fwd:"),
                    bodyHtml = quoteForForward(emailSender, emailSubject, emailPreview),
                    attachments = orderedForwardAttachments(),
                )
            }
        }
    }

    /** Attachment order is the sender's, not the order the user happened to tap them in. */
    private fun orderedForwardAttachments(): List<com.urlxl.mail.mail.OutgoingAttachment> =
        attachmentInfos.mapNotNull { downloadedAttachments[it.index] }
            .ifEmpty { downloadedAttachments.values.toList() }

    private fun rememberForForwarding(index: Int, downloaded: com.urlxl.mail.mail.DownloadedAttachment) {
        downloadedAttachments[index] = com.urlxl.mail.mail.OutgoingAttachment(
            name = downloaded.name,
            mimeType = downloaded.mimeType,
            dataBase64 = android.util.Base64.encodeToString(downloaded.bytes, android.util.Base64.NO_WRAP),
            size = downloaded.bytes.size,
        )
    }

    /**
     * The only screen that tells the user what happened to an encrypted message. Silence here is
     * what the old build did, and it read as "this email is blank".
     */
    private fun renderPgpBar(
        state: PgpMessageState,
        pgpDecryptError: String,
        webmailUrl: String?,
    ) {
        if (state == PgpMessageState.NONE) {
            pgpBar.visibility = View.GONE
            return
        }
        pgpBar.visibility = View.VISIBLE
        btnOpenInWebmail.visibility = View.GONE

        when (state) {
            PgpMessageState.DECRYPT_FAILED ->
                pgpText.text = getString(R.string.email_pgp_decrypt_failed, pgpDecryptError)
            PgpMessageState.DECRYPTED_BY_SERVER ->
                pgpText.text = getString(R.string.email_pgp_decrypted_by_server)
            PgpMessageState.CLIENT_PROTECTED -> {
                if (webmailUrl == null) {
                    pgpText.text = getString(R.string.email_pgp_client_protected) +
                        "\n" + getString(R.string.email_pgp_no_webmail)
                } else {
                    pgpText.text = getString(R.string.email_pgp_client_protected)
                    btnOpenInWebmail.visibility = View.VISIBLE
                    // Handed to the system, so an installed PWA or the user's browser opens it
                    // with the session it already has — deliberately not an in-app WebView,
                    // which shares no session and would put an account-password field inside
                    // this app.
                    btnOpenInWebmail.setOnClickListener {
                        val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(webmailUrl))
                        if (intent.resolveActivity(packageManager) != null) {
                            startActivity(intent)
                        } else {
                            Toast.makeText(this, R.string.email_pgp_no_webmail, Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            PgpMessageState.BODY_UNAVAILABLE ->
                pgpText.text = getString(R.string.email_pgp_body_unavailable)
            PgpMessageState.NONE -> Unit
        }
    }

    private fun loadAttachments(emailId: String, emailFolder: String) {
        ioExecutor.execute {
            val outcome = mailRepository.listAttachments(emailId, emailFolder)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val infos = (outcome as? MailOutcome.Success)?.value.orEmpty()
                renderAttachments(emailId, emailFolder, infos)
            }
        }
    }

    private fun renderAttachments(emailId: String, emailFolder: String, infos: List<AttachmentInfo>) {
        attachmentInfos = infos
        val label = findViewById<TextView>(R.id.emailAttachmentsLabel)
        val chips = findViewById<ChipGroup>(R.id.emailAttachmentChips)
        chips.removeAllViews()
        if (infos.isEmpty()) {
            label.visibility = View.GONE
            chips.visibility = View.GONE
            return
        }
        label.visibility = View.VISIBLE
        chips.visibility = View.VISIBLE
        // Read once, not once per chip: this opens a SharedPreferences file, and it was inside
        // the loop.
        val protectionEnabled = com.urlxl.mail.security.SecurityRuntime
            .graph(this).hostileLocationSettings.isEnabled()
        infos.forEach { info ->
            val chip = Chip(this).apply {
                text = if (protectionEnabled) "👁 ${info.name}" else "📎 ${info.name}"
                setOnClickListener { downloadAttachment(emailId, emailFolder, info) }
            }
            applyPillChipTheme(this, chip)
            chips.addView(chip)
        }
    }

    private fun downloadAttachment(emailId: String, emailFolder: String, info: AttachmentInfo) {
        val hostileLocationProtectionEnabled = com.urlxl.mail.security.SecurityRuntime
            .graph(this).hostileLocationSettings.isEnabled()
        val action = com.urlxl.mail.security.attachmentActionFor(hostileLocationProtectionEnabled)
        val loadingMessage = if (action == com.urlxl.mail.security.AttachmentAction.VIEW_EPHEMERAL) {
            getString(R.string.attachment_opening, info.name)
        } else {
            getString(R.string.attachment_downloading, info.name)
        }
        Toast.makeText(this, loadingMessage, Toast.LENGTH_SHORT).show()
        ioExecutor.execute {
            val outcome = mailRepository.downloadAttachment(emailId, emailFolder, info.index)
            val downloaded = (outcome as? MailOutcome.Success)?.value
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (downloaded == null) {
                    val message = outcome.userFacingMessage() ?: getString(R.string.attachment_save_failed, info.name)
                    Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                    return@runOnUiThread
                }
                rememberForForwarding(info.index, downloaded)
                when (action) {
                    com.urlxl.mail.security.AttachmentAction.VIEW_EPHEMERAL -> viewAttachmentEphemerally(downloaded)
                    com.urlxl.mail.security.AttachmentAction.SAVE_TO_DOWNLOADS -> {
                        val saved = saveToDownloads(downloaded.name, downloaded.mimeType, downloaded.bytes)
                        val message = if (saved) getString(R.string.attachment_saved, info.name) else getString(R.string.attachment_save_failed, info.name)
                        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /** Hostile Location Protection path: hands the bytes to [com.urlxl.mail.security.EphemeralAttachmentBytes]
     *  (never written to disk) and launches a viewer via ACTION_VIEW — nothing is saved anywhere. */
    private fun viewAttachmentEphemerally(downloaded: com.urlxl.mail.mail.DownloadedAttachment) {
        // Normalise the MIME type before it selects a handler. It comes from the sender's
        // Content-Type, which the relay passes through unfiltered, and an implicit intent with
        // exactly one matching activity is launched directly with no chooser — so an obscure type
        // like application/vnd.kypost-x let a co-installed app guarantee itself sole-resolver status
        // and silently receive the decrypted bytes, on the one path whose purpose is that the
        // plaintext never leaves the app's control.
        val mimeType = downloaded.mimeType.takeIf { it in VIEWABLE_MIME_TYPES } ?: "application/octet-stream"
        val uri = com.urlxl.mail.security.EphemeralAttachmentBytes.register(downloaded.bytes, mimeType)
        val view = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        // Always show the chooser, so no app can become a silent default for the attachment type.
        val chooser = Intent.createChooser(view, getString(R.string.attachment_open_with))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        runCatching { startActivity(chooser) }.onFailure {
            Toast.makeText(this, getString(R.string.attachment_save_failed, downloaded.name), Toast.LENGTH_LONG).show()
        }
    }

    /** Writes bytes into the shared Downloads collection via MediaStore (no storage permission
     *  needed on the app's minSdk 31). Returns false if the insert or stream write fails. */
    private fun saveToDownloads(name: String, mimeType: String, bytes: ByteArray): Boolean {
        val resolver = contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, mimeType.ifBlank { "application/octet-stream" })
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        return runCatching {
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return false
            resolver.openOutputStream(uri)?.use { it.write(bytes) } ?: return false
            true
        }.getOrDefault(false)
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
        applyDetailChrome()
    }

    private fun applyDetailChrome() {
        val palette = getStoredThemePalette(this)
        divider.setBackgroundColor(Color.parseColor(palette.line))
        webView.setBackgroundColor(Color.parseColor(palette.bg))
        // Same warning-callout treatment ComposeActivity's keyless-recipient
        // notice uses, so a security warning looks the same everywhere.
        applyWarningCalloutTheme(this, phishingBar)
        actionButtons.forEach { applyIconButtonTheme(this, it) }
    }

    private fun runMailActionAndFinish(actionLabel: String, emailId: String, action: (MailRepository) -> MailOutcome<Unit>) {
        Toast.makeText(this, actionLabel, Toast.LENGTH_SHORT).show()
        // Reporting, not fire-and-forget: the row is removed optimistically, so a failure the user
        // never hears about reads as "it worked" until the message reappears on the next resync.
        MailBackgroundExecutor.submitReporting(this, actionLabel) { action(mailRepository) }
        // Tell InboxActivity which row to drop immediately, mirroring its own swipe-to-archive/
        // delete optimistic removal. Without this, returning here re-triggers InboxActivity's
        // onStart refresh, which races the still-in-flight mutation above and can redraw the row
        // we just "removed" — the mutation still lands, it just looks like the button did nothing.
        setResult(RESULT_OK, Intent().putExtra(EXTRA_REMOVED_EMAIL_ID, emailId))
        finish()
    }

    private fun openCompose(
        to: String,
        subject: String,
        bodyHtml: String,
        attachments: List<com.urlxl.mail.mail.OutgoingAttachment> = emptyList(),
    ) {
        val intent = Intent(this, ComposeActivity::class.java)
        intent.putExtra(ComposeActivity.EXTRA_TO, to)
        intent.putExtra(ComposeActivity.EXTRA_SUBJECT, subject)
        intent.putExtra(ComposeActivity.EXTRA_BODY_HTML, bodyHtml)
        // Handed through the process-scoped cache rather than the Intent: a 25 MB base64 payload
        // in an Intent extra is well past Binder's ~1 MB transaction limit and would throw
        // TransactionTooLargeException. Both Activities are in this process, so a handoff object
        // is both correct and cheaper than re-downloading.
        if (attachments.isNotEmpty()) ForwardAttachmentHandoff.put(attachments)
        startActivity(intent)
    }

    /** Opens a link the user tapped inside an email in the system browser. Failure is silent-ish
     *  (a toast) rather than a crash: an email can name any scheme, including ones no app handles.
     *
     *  CATEGORY_BROWSABLE narrows resolution to components that accept being driven by untrusted
     *  content, which is what K-9 does on the same path — without it, an email link can reach an
     *  installed app's non-browsable exported activities. Callers must already have checked the
     *  scheme and the user gesture; see [SAFE_LINK_SCHEMES]. */
    private fun openExternally(uri: android.net.Uri) {
        val intent = Intent(Intent.ACTION_VIEW, uri)
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
            .onFailure { Toast.makeText(this, R.string.email_link_no_handler, Toast.LENGTH_SHORT).show() }
    }

    /**
     * The quoted original, as HTML.
     *
     * This used to interpolate `emailPreview`, which is `body.take(140)` of the sender's **raw
     * HTML** (see `RelayMailSource.toUiEmail`). Replying to any HTML message therefore quoted 140
     * characters of markup — `<div dir="ltr"><div class="gmail_quote"><div dir="l` — and
     * forwarding sent that instead of the message. The real body is already fetched by this
     * screen's own body load; [fetchedBodyHtml] holds it.
     *
     * Falls back to the escaped preview only when the body genuinely is not available (an
     * uncached message under Hostile Location Protection, or a client-protected one), which is the
     * same condition the PGP bar already reports to the user.
     */
    private fun quoteForReply(sender: String, preview: String): String {
        val quoted = fetchedBodyHtml?.takeIf { it.isNotBlank() } ?: TextUtils.htmlEncode(preview)
        return "<br><br><div>${TextUtils.htmlEncode(sender)} wrote:</div>" +
            "<blockquote style=\"margin:0 0 0 0.8ex;border-left:1px solid #ccc;padding-left:1ex\">" +
            quoted +
            "</blockquote>"
    }

    private fun quoteForForward(sender: String, subject: String, preview: String): String {
        val quoted = fetchedBodyHtml?.takeIf { it.isNotBlank() } ?: TextUtils.htmlEncode(preview)
        return "<br><br><div>---------- Forwarded message ----------</div>" +
            "<div>From: ${TextUtils.htmlEncode(sender)}</div>" +
            "<div>Subject: ${TextUtils.htmlEncode(subject)}</div><br>" +
            quoted
    }

    private fun withPrefix(subject: String, prefix: String): String {
        return if (subject.trim().startsWith(prefix, ignoreCase = true)) subject else "$prefix $subject"
    }

    // Delegates to mail/AddressText.kt so the rule is unit-tested and stays
    // identical to the webmail and Linux clients -- see AddressTextTest for why
    // a display name must never win over the real angle-addr.
    private fun extractAddress(raw: String): String = addressFromHeader(raw)

    override fun onDestroy() {
        super.onDestroy()
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
    }

    companion object {
        private const val TAG = "EmailDetailActivity"

        const val EXTRA_REMOVED_EMAIL_ID = "removed_email_id"

        /** Schemes an email link may open. `intent:`, `file:`, `content:` and any third-party
         *  app's custom scheme are refused: routing untrusted sender content into an arbitrary
         *  installed app's deep link is not something a mail body gets to do. */
        private val SAFE_LINK_SCHEMES = setOf("http", "https", "mailto", "tel")

        /** MIME types the ephemeral-view path will hand to an external viewer as-declared. Anything
         *  else is downgraded to `application/octet-stream`, which every file handler competes for —
         *  so a sender cannot pick a type only their own app claims. */
        private val VIEWABLE_MIME_TYPES = setOf(
            "application/pdf",
            "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic",
            "text/plain",
            "audio/mpeg", "audio/mp4", "audio/ogg",
            "video/mp4", "video/webm",
        )

        /** Cheap heuristic for "does this body reference remote content" (images, iframes, media,
         *  stylesheets) — only used to decide whether the "Show images" bar is worth showing, not
         *  a security control itself (all network loads are blocked regardless via
         *  [android.webkit.WebSettings.setBlockNetworkLoads]).
         *
         *  The tag interior is bounded rather than `[^>]*`. Unbounded, this was quadratic on
         *  sender-chosen input and — unlike [stripImportant] — had no length cap and ran on every
         *  message on every theme: `[^>]*` scanned to end-of-body from each of the many `<img`
         *  positions, then backtracked looking for the attribute. Measured on-device at ~21.8s for
         *  a 128KB body of repeated `<img`, scaling 4x per doubling. 2KB is far past any real tag. */
        private val REMOTE_IMAGE_PATTERN = Regex(
            """<(?:img|link|iframe|video|audio|source|embed|object)\b[^>]{0,2048}?\s(?:src|href|poster|data)\s*=\s*["']https?://""",
            RegexOption.IGNORE_CASE,
        )
    }
}

/** Wraps [bodyToRender] (the email's own, untrusted HTML) in a themed document for [WebView].
 *
 *  Pulled out of the `onCreate` body-loading callback so it's unit-testable without a
 *  Context-backed WebView/Activity (same extraction rationale as [mergedContactDto] in
 *  `ContactEditActivity`).
 *
 *  For a light [palette] this only sets `body`'s own color/background — the same as before this
 *  function existed, and enough, since a light palette already looks like a typical email's
 *  default white-background/dark-text design.
 *
 *  For a dark [palette], a plain `body` rule isn't enough: most email HTML hardcodes its own
 *  light-mode colors (inline `style="color:#000"`, legacy `bgcolor` attributes, or a `<style>`
 *  block of its own), and those win over `body`'s inherited color/background at every descendant
 *  that sets its own — producing exactly the reported bug (black text on the app's dark background
 *  where an email set its own text color but not a background, or black-on-white where it set
 *  both, depending on what that particular email happens to override). CSS `!important` beats a
 *  plain (non-`!important`) declaration regardless of origin or specificity, so a wildcard
 *  `!important` override here reliably wins over whatever the email brought — *unless* the email's
 *  own declaration is itself `!important` too, which real templates increasingly do specifically to
 *  defend their background/text colors against Gmail/Outlook/Apple Mail's own automatic dark-mode
 *  recoloring. When both sides are `!important`, the cascade falls back to specificity/origin, and
 *  an inline `style="...!important"` attribute always outranks any external stylesheet rule — no
 *  selector on our side, however specific, can out-rank it (that's exactly the residual bug: an
 *  email with an `!important`-marked white background stayed white-on-white, our forced light text
 *  landing on top of it unread). [stripImportant] removes every literal `!important` from the
 *  email's own markup first, so nothing in it can compete on importance at all — our `!important`
 *  rules then win unconditionally, regardless of what selector or attribute the email used, per the
 *  CSS cascade's origin/importance step being resolved before specificity is ever considered.
 *  Does not need JavaScript (disabled in this WebView) or WebView's own force-dark APIs (which
 *  follow the *system* day/night setting, not this app's independent, non-system-linked theme
 *  picker). Links are re-forced to the palette's accent color after the wildcard rule so they don't
 *  get flattened to the same color as body text.
 *
 *  [isDark] (from [isDarkPalette]) is a caller-supplied `Boolean` rather than computed in here from
 *  [palette] directly so this function stays free of any `android.graphics.Color` call — same
 *  reasoning as [mergedContactDto]'s extraction: a plain-JVM unit test can exercise it with no
 *  Android framework/Robolectric dependency. */
internal fun buildEmailBodyHtml(bodyToRender: String, palette: ThemePalette, monoFontFace: String, isDark: Boolean): String {
    val darkModeOverrideCss = if (isDark) {
        """
        html, body {
            background-color: ${palette.bg} !important;
            color: ${palette.inkStrong} !important;
        }
        body * {
            background-color: transparent !important;
            color: ${palette.inkStrong} !important;
        }
        body a, body a * {
            color: ${palette.accent} !important;
        }
        """.trimIndent()
    } else {
        ""
    }
    val body = if (isDark) stripImportant(bodyToRender) else bodyToRender
    return """
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <style>
                $monoFontFace
                body {
                    font-family: 'IBM Plex Mono', monospace;
                    font-size: 16px;
                    line-height: 1.5;
                    color: ${palette.inkStrong};
                    background-color: ${palette.bg};
                    margin: 0;
                    padding: 8px;
                    word-break: break-word;
                }
                a { color: ${palette.accent}; }
                img { max-width: 100%; height: auto; }
                pre { white-space: pre-wrap; }
                $darkModeOverrideCss
            </style>
        </head>
        <body>$body</body>
        </html>
    """.trimIndent()
}

// A CSS comment produces zero tokens during tokenization (CSS Syntax §4) and is fully
// transparent between any two other tokens — including between `!` and `important` — so it
// must be removed everywhere before the `!important` check below, not just matched around.
//
// Written in the standard non-backtracking form rather than a lazy `.*?` with DOT_MATCHES_ALL:
// the lazy version degrades to O(n^2) over the whole body when the closing `*/` is missing, and
// the input here is chosen by the sender.
private val CSS_COMMENT = Regex("""/\*[^*]*\*+(?:[^/*][^*]*\*+)*/""")

/** Bodies past this size skip [stripImportant] entirely. It is a rendering nicety for dark mode,
 *  not a security control, so on a multi-megabyte email it is not worth the scan — and refusing to
 *  scan is a bounded, predictable outcome where an unbounded regex pass is not. */
private const val STRIP_IMPORTANT_MAX_LENGTH = 512 * 1024

// A CSS escape sequence is a backslash followed by 1-6 hex digits, optionally followed by one
// whitespace terminator (CSS Syntax §4.3.7), and decodes to a single Unicode code point — so a
// sender can spell any letter of "important" as an escape (e.g. `!\49 mportant` decodes to
// `!Important`) instead of the literal character.
//
// Six hex digits reach 0xFFFFFF, well past the 0x10FFFF ceiling of the Unicode codespace, so the
// pattern accepts values that are not code points at all. See [decodeCssEscapes] for why that has
// to be handled rather than passed straight to Character.toChars.
private val CSS_ESCAPE = Regex("""\\([0-9a-fA-F]{1,6})\s?""")

/**
 * Decodes the CSS escape sequences in [candidate], leaving anything that is not a valid code point
 * as the literal text the sender wrote.
 *
 * `Character.toChars` **throws** `IllegalArgumentException` for a code point above 0x10FFFF, and
 * [CSS_ESCAPE] matches up to six hex digits, so `!\110000 mportant` in a message body used to throw
 * out of [stripImportant]. That ran on [EmailDetailActivity]'s `ioExecutor`, where an uncaught
 * exception is a process kill — and since the message stays in the mailbox, every reopen crashed
 * again. A remote sender got a persistent, un-clearable denial of service on the mail client by
 * sending one styled `<p>`.
 *
 * Out-of-range escapes are left verbatim rather than dropped: CSS says an escape outside the
 * codespace is a parse error that renders as U+FFFD, so it can never spell a letter of "important"
 * either way, and leaving the text alone keeps this function's "over-matching is harmless,
 * under-matching is not" bias pointing the safe direction.
 */
private fun decodeCssEscapes(candidate: String): String =
    CSS_ESCAPE.replace(candidate) { escape ->
        val codePoint = escape.groupValues[1].toIntOrNull(16)
        if (codePoint != null && Character.isValidCodePoint(codePoint)) {
            String(Character.toChars(codePoint))
        } else {
            escape.value
        }
    }

// `!` followed by up to 24 characters of letters, whitespace, or CSS escapes — a generous
// window for "important" plus incidental whitespace/escapes, bounded so we don't scan arbitrarily
// far into unrelated text after an unrelated `!`.
//
// The leading whitespace run is BOUNDED, not `\s*`. Unbounded it gave the pattern no literal first
// character, so at every offset in the body the engine consumed whitespace to end-of-input and then
// backtracked looking for `!` — quadratic, and reachable from a single email with no `!` in it at
// all. Measured on a 512KB body of nothing but spaces: ~3.9 minutes on a desktop JVM, ~20-35
// minutes on-device. A bounded run keeps the whitespace *consumed* (so `color:red !important`
// collapses to `color:red`, as the tests expect) while capping the work per position at 8 tries.
// Real CSS has one space here; 8 is already generous.
private val BANG_CANDIDATE = Regex("""\s{0,8}!((?:\\[0-9a-fA-F]{1,6}\s?|[A-Za-z\s]){1,24})""")

/** Strips every `!important` from [html] — see [buildEmailBodyHtml]'s doc for why this is what
 *  actually closes the override gap for `!important`-defended email styling. Tolerant of the two
 *  CSS-spec-legal ways a sender can split the token to dodge a plain text search: a CSS comment
 *  inserted anywhere (removed globally, since a comment has no display semantics to preserve),
 *  and any letter of "important" written as a CSS escape sequence instead of the literal
 *  character (decoded only within the captured `!`-prefixed candidate, so escape sequences
 *  elsewhere in the email body — which do have display semantics — are left untouched). A
 *  blunt text-level removal rather than a real CSS/HTML parse: this app has no HTML parser
 *  dependency, the input is untrusted, and correctness only requires that no `!important`
 *  survive anywhere reachable by a CSS declaration (inline `style=` attributes or an embedded
 *  `<style>` block) — over-matching a stray `!important` inside, say, an HTML comment or
 *  unrendered text is harmless, since removing it doesn't change what's displayed. */
internal fun stripImportant(html: String): String {
    if (html.length > STRIP_IMPORTANT_MAX_LENGTH) return html
    val withoutComments = html.replace(CSS_COMMENT, "")
    return BANG_CANDIDATE.replace(withoutComments) { match ->
        val decoded = decodeCssEscapes(match.groupValues[1])
        if (decoded.trim().equals("important", ignoreCase = true)) "" else match.value
    }
}
