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
import com.urlxl.mail.mail.QuotedHtmlSanitizer
import com.urlxl.mail.mail.addressFromHeader
import com.urlxl.mail.mail.userFacingMessage
import com.urlxl.mail.pgp.AndroidVaultOpener
import com.urlxl.mail.pgp.EncryptedMessageReader
import com.urlxl.mail.pgp.PayloadSource
import com.urlxl.mail.pgp.PgpMessageState
import com.urlxl.mail.pgp.PgpPayloadClient
import com.urlxl.mail.pgp.PgpSignatureState
import com.urlxl.mail.pgp.ReadOutcome
import com.urlxl.mail.pgp.openWebmail
import com.urlxl.mail.pgp.pgpMessageStateOf
import com.urlxl.mail.pgp.rendersNothing
import com.urlxl.mail.pgp.webmailMessageUrl
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory
import java.util.concurrent.Executors
import com.urlxl.mail.security.LockedActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class EmailDetailActivity : LockedActivity() {

    private val ioExecutor = Executors.newSingleThreadExecutor()
    private lateinit var mailRepository: MailRepository
    private lateinit var actionButtons: List<ImageButton>

    /** [actionReply], [actionReplyAll] and [actionForward] — the subset of [actionButtons] that
     *  [applyReplyForwardAvailability] visually marks as unavailable for a
     *  [PgpMessageState.CLIENT_PROTECTED] message. Kept as its own field, rather than re-derived
     *  from [actionButtons] by position, so which three buttons this reaches cannot silently drift
     *  if [actionButtons]'s order ever changes. */
    private lateinit var replyForwardButtons: List<ImageButton>

    /**
     * The state Reply/Reply-All/Forward's click listeners check via [mayReplyOrForward] before
     * doing anything.
     *
     * Fail closed. [renderBody] runs on a background thread and, for an uncached message, makes a
     * network round trip before it can report a real [PgpMessageState] — see its own KDoc on
     * `bodyUnavailable` — and may never report one at all if it throws (caught by the `runCatching`
     * around its call site, which only toasts). Defaulting to [PgpMessageState.NONE] here would
     * leave Reply live for that entire window on exactly the messages this task exists to protect.
     * Set to the real, encrypted-or-not verdict as soon as the Intent extra is read in `onCreate`
     * (synchronous, no fetch involved), then overwritten with the definitive value once
     * [renderBody] resolves it.
     */
    private var replyForwardState: PgpMessageState = PgpMessageState.CLIENT_PROTECTED
    private lateinit var divider: View
    private lateinit var webView: WebView
    private lateinit var lockedPlaceholder: android.widget.ImageView
    private lateinit var imagesBlockedBar: View
    private lateinit var btnShowImages: Button
    private lateinit var phishingBar: TextView
    private lateinit var pgpBar: View
    private lateinit var pgpText: TextView
    private lateinit var subjectView: TextView
    private lateinit var fromView: TextView
    private lateinit var btnOpenInWebmail: Button
    private lateinit var btnDecryptHere: Button
    private lateinit var btnRetryPayload: Button
    private var lastAppliedThemeName: String = ""
    private var lastRenderedHtml: String? = null

    /** Set in the [PgpMessageState.CLIENT_PROTECTED] branch of [renderPgpBar] when no webmail URL
     *  could be resolved for this message. [showLocked] appends [R.string.email_pgp_no_webmail] in
     *  that case, since every [ReadOutcome] notice below was written assuming a webmail fallback
     *  exists — several end "...or open it in webmail" with no button and no address on screen when
     *  it does not. */
    private var webmailUnavailable: Boolean = false

    /** Guards [attemptDecrypt] against a second attempt landing while the first is still in flight
     *  — e.g. a tap on Decrypt while the automatic (unlockIfNeeded = false) attempt is still
     *  running. Without this, an outcome that resolves out of order (a stale [ReadOutcome.Cancelled]
     *  arriving after a real [ReadOutcome.Decrypted]) could regress a message already on screen back
     *  to the padlock. */
    private var decryptJob: Job? = null

    /** The message's real body, once the background fetch has answered. Reply/Forward quote this;
     *  see [quoteForReply] for why the 140-character preview was never an acceptable substitute. */
    private var fetchedBodyHtml: String? = null

    /** The relay's verdict on this message's OpenPGP signature, from the detail Intent —
     *  initially. For a [PgpMessageState.CLIENT_PROTECTED] message this app can decrypt locally,
     *  it is overwritten with the local verdict from [displaySignatureVerdict] once that decrypt
     *  finishes, so it does not stay the relay's verdict for the message's whole lifetime on
     *  screen. Rendered by both [renderPgpBar] and [showLocked] — see [PgpSignatureState] for why
     *  it is separate from [PgpMessageState]. */
    private var pgpSignatureState: PgpSignatureState = PgpSignatureState.NONE

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
        // Refines the fail-closed CLIENT_PROTECTED default above as soon as we synchronously know
        // better: an unencrypted message was never going to become CLIENT_PROTECTED, so there is no
        // reason to hold its Reply button hostage to the body fetch below. An encrypted one keeps
        // the fail-closed default until renderBody reports the real state. See
        // initialReplyForwardState's own KDoc for why this is a pure function rather than the
        // ternary it replaced.
        replyForwardState = initialReplyForwardState(pgpEncrypted)
        val pgpDecryptError = intent.getStringExtra("email_pgp_decrypt_error").orEmpty()
        pgpSignatureState = com.urlxl.mail.pgp.pgpSignatureStateOf(
            pgpSigned = intent.getBooleanExtra("email_pgp_signed", false),
            pgpVerified = intent.getBooleanExtra("email_pgp_verified", false),
        )
        val phishingFlagged = intent.getBooleanExtra("email_suspicious", false)

        setTitle(R.string.email_title)

        subjectView = findViewById(R.id.emailSubject)
        fromView = findViewById(R.id.emailFrom)
        webView = findViewById(R.id.emailWebView)
        lockedPlaceholder = findViewById(R.id.emailLockedPlaceholder)
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
        btnDecryptHere = findViewById(R.id.btnDecryptHere)
        btnRetryPayload = findViewById(R.id.btnRetryPayload)
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
        replyForwardButtons = listOf(actionReply, actionReplyAll, actionForward)
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
            // Checked here, not via isEnabled = false: a disabled ImageButton's onTouchEvent
            // returns before performClick ever runs, which would make this very explanation
            // unreachable. See applyReplyForwardAvailability's KDoc for the rest of the reasoning
            // (fail-closed default, alpha-only visual signal, contentDescription for TalkBack).
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = extractAddress(emailSender),
                    subject = withPrefix(emailSubject, "Re:"),
                    bodyHtml = quoteForReply(emailSender, quoted),
                )
            }
        }
        actionReplyAll.setOnClickListener {
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val recipients = (listOf(extractAddress(emailSender)) + toRecipients.map(::extractAddress) + ccRecipients.map(::extractAddress))
                .distinct()
                .filter { it.isNotBlank() }
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = recipients.joinToString(", "),
                    subject = withPrefix(emailSubject, "Re:"),
                    bodyHtml = quoteForReply(emailSender, quoted),
                )
            }
        }
        actionForward.setOnClickListener {
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
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
            runCatching { renderBody(emailId, emailFolder, emailSender, emailPreview, pgpEncrypted, pgpDecryptError, loading) }
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
        emailSender: String,
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
        // Computed from the same inputs the line above used, so the notice cannot claim the screen is
        // empty while something is on it, or stay silent while it is not.
        val nothingToRender = rendersNothing(pgpState, content?.html, emailPreview)
        // Cosmetic heuristic, so on a multi-megabyte sender-chosen body a bounded "assume none"
        // beats an unbounded scan. Belt-and-braces with the bounded tag interior in the pattern.
        val hasRemoteImages = bodyToRender.length <= REMOTE_IMAGE_SCAN_MAX_LENGTH &&
            REMOTE_IMAGE_PATTERN.containsMatchIn(bodyToRender)
        val palette = getStoredThemePalette(this)
        val monoFontFace = ibmPlexMonoFontFaceCss(this)

        val htmlContent = buildEmailBodyHtml(bodyToRender, palette, monoFontFace, isDark = isDarkPalette(palette))
        // Resolved off the main thread with the URL it builds — pairingForAuthenticatedCall
        // reads Keystore-backed EncryptedSharedPreferences, which is disk I/O. Both are kept:
        // openWebmail re-derives the origin from serverUrl to check the URL it is handed.
        val serverUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
            PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
        } else {
            null
        }
        val webmailUrl = serverUrl?.let { webmailMessageUrl(it, emailFolder, emailId) }

        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            lastRenderedHtml = htmlContent
            // Not `bodyToRender`: that is blanked for the PGP states with nothing to show. Enforced
            // here too, not just emergent from the server's empty CLIENT_PROTECTED body: the spec's
            // non-negotiable rule is that a local decrypt must never reach this property, and this
            // makes that explicit rather than relying on the server having nothing to assign.
            fetchedBodyHtml = content?.html?.takeIf { pgpState != PgpMessageState.CLIENT_PROTECTED }
            webView.loadDataWithBaseURL(null, htmlContent, "text/html", "utf-8", null)
            loading.visibility = android.view.View.GONE
            imagesBlockedBar.visibility = if (hasRemoteImages) View.VISIBLE else View.GONE
            renderPgpBar(pgpState, pgpDecryptError, serverUrl, webmailUrl, nothingToRender, emailFolder, emailId, emailSender)
            applyReplyForwardAvailability(pgpState)
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
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = "",
                    subject = withPrefix(emailSubject, "Fwd:"),
                    bodyHtml = quoteForForward(emailSender, emailSubject, quoted),
                    attachments = orderedForwardAttachments(),
                )
            }
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
     *
     * [serverUrl] is passed in beside [webmailUrl] rather than read from a field so the two are
     * provably from the same render pass: the click listener below re-checks the link against the
     * origin it was built from, and a field could have been overwritten by a later render in
     * between.
     */
    private fun renderPgpBar(
        state: PgpMessageState,
        pgpDecryptError: String,
        serverUrl: String?,
        webmailUrl: String?,
        /** Decided by [rendersNothing] in the same render pass that chose the body, so this cannot
         *  disagree with what was actually put on screen. */
        nothingToRender: Boolean,
        /** The account mailbox (IMAP folder) and message id this render is for, plus the sender
         *  exactly as displayed — needed only to kick off [attemptDecrypt] from the
         *  [PgpMessageState.CLIENT_PROTECTED] branch below. */
        mailbox: String,
        messageId: String,
        sender: String,
    ) {
        // A message can be perfectly readable and still be signed by someone other than who it
        // claims to be from, so the signature verdict is rendered even when there is no encryption
        // state to report. This was computed by the relay, carried through every layer and written
        // to Room behind its own migration — and then never shown, so a forged-signature message
        // displayed as ordinary mail while webmail flagged it.
        val signatureNotice = signatureNoticeFor(pgpSignatureState)

        if (state == PgpMessageState.NONE) {
            // The blank-screen case this function's KDoc warns about, still open for NONE after it
            // was closed for every encrypted state. An encrypted message the server has not warmed
            // arrives with pgpEncrypted false and no body, lands here, and rendered as silence.
            // A signature notice, where there is one, wins: it is a stronger statement than "nothing
            // to show" and the two would otherwise be concatenated into a contradiction.
            val notice = signatureNotice
                ?: getString(R.string.email_no_content).takeIf { nothingToRender }
            pgpBar.visibility = if (notice == null) View.GONE else View.VISIBLE
            btnOpenInWebmail.visibility = View.GONE
            pgpText.text = notice.orEmpty()
            pgpText.visibility = if (notice == null) View.GONE else View.VISIBLE
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
                webmailUnavailable = serverUrl == null || webmailUrl == null
                // Defer Open in Webmail visibility to renderReadOutcome to avoid a flash
                // of the fallback button before the on-device decrypt (attemptDecrypt with
                // unlockIfNeeded=false) resolves. The success path (Decrypted) and the
                // NeedsUnlock/Cancelled paths both hide webmail; only terminal failures
                // show it via showLocked's webmailUnavailable guard.
                if (serverUrl != null && webmailUrl != null) {
                    btnOpenInWebmail.setOnClickListener {
                        // A Custom Tab where one is available: the user's real browser, with the
                        // session webmail already holds, rendered over this activity so a back
                        // gesture comes straight back to the message list. See WebmailTab for why
                        // this is not the in-app WebView the old comment here ruled out.
                        if (!openWebmail(this, serverUrl, webmailUrl)) {
                            Toast.makeText(this, R.string.email_pgp_no_handler, Toast.LENGTH_LONG).show()
                        }
                    }
                }
                btnOpenInWebmail.visibility = View.GONE
                // No pointless "This message is end-to-end encrypted..." paragraph — show only
                // actionable buttons (Decrypt Email vs Open in webmail). The signature badge,
                // if any, is rendered at the end of this function.
                pgpText.text = ""
                // Explicit taps always may prompt; only the automatic attempt below is silent when
                // the key is not held.
                btnDecryptHere.setOnClickListener {
                    attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = true)
                }
                btnRetryPayload.setOnClickListener {
                    attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = true)
                }
                // Automatic only when the key is already held: unlockIfNeeded = false means this
                // never raises a biometric sheet on a message the user simply opened.
                attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = false)
            }
            PgpMessageState.BODY_UNAVAILABLE ->
                pgpText.text = getString(R.string.email_pgp_body_unavailable)
            PgpMessageState.NONE -> Unit
        }

        // Prepended, not appended: a signature that does not match the sender is the more urgent of
        // the two facts, and it should not sit below a paragraph about decryption.
        if (signatureNotice != null) {
            val current = pgpText.text.toString()
            pgpText.text = if (current.isBlank()) signatureNotice else signatureNotice + "\n\n" + current
        }
        pgpText.visibility = if (pgpText.text.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    /**
     * Records the definitive [PgpMessageState] for Reply/Reply-All/Forward's own click-time check
     * ([replyForwardState]) and updates the three buttons' visual state to match.
     *
     * `POST /api/mail/draft` uploads the draft to the server. Quoting a decrypted body into a
     * reply would hand the server the plaintext of a message this whole mode exists to keep from
     * it — at one tap, with no warning. There is no encrypted send path in the app yet, so there
     * is no safe destination for any of these three actions.
     *
     * Unconditional rather than gated on decrypt success — see [mayReplyOrForward] — so a button
     * never starts working once a message opens; that would teach the user a rule that is not
     * true.
     *
     * Deliberately does NOT set `isEnabled = false`. `View.onTouchEvent` returns before
     * `performClick()` ever runs on a disabled view, which would make the explanatory Toast in
     * each click listener unreachable dead code — a grey button the user taps for nothing. `alpha`
     * carries the visual signal instead, and [contentDescription][View.setContentDescription]
     * carries the same "why" to TalkBack that `isEnabled = false` would otherwise have announced
     * for free (as "disabled", with no reason) — the same substitution [EmailAdapter] already makes
     * for the inbox row's own PGP markers, and for the same reason: an emoji or a plain disabled
     * state tells a screen-reader user nothing a sighted user wouldn't also be missing.
     *
     * Only touches the buttons when [pgpState] blocks them. `renderBody` calls this exactly once
     * per Activity instance, and every one of these `ImageButton`s already carries its own
     * `android:contentDescription` ("Reply", "Reply all", "Forward") from the layout — clearing
     * that unconditionally on the allowed path would silently strip those labels from every
     * ordinary message, not just this one's.
     */
    private fun applyReplyForwardAvailability(pgpState: PgpMessageState) {
        replyForwardState = pgpState
        if (mayReplyOrForward(pgpState)) return
        val notice = getString(R.string.email_pgp_reply_disabled)
        replyForwardButtons.forEach { button ->
            button.alpha = 0.4f
            button.contentDescription = notice
        }
    }

    /** The sentence for one [PgpSignatureState], or null when there is nothing to say. Shared by
     *  [renderPgpBar] (server-side verdicts) and [renderReadOutcome] (on-device verdicts) so the
     *  wording cannot drift between the two paths that can produce the same six states. */
    private fun signatureNoticeFor(state: PgpSignatureState): String? = when (state) {
        PgpSignatureState.VERIFIED_CONFIRMED -> "✅ " + getString(R.string.email_pgp_signature_confirmed)
        PgpSignatureState.VERIFIED_SEEN_BEFORE -> "🟢 " + getString(R.string.email_pgp_signature_seen_before)
        PgpSignatureState.SIGNER_UNKNOWN -> "⬜ " + getString(R.string.email_pgp_signature_signer_unknown)
        PgpSignatureState.INVALID -> "⚠️ " + getString(R.string.email_pgp_signature_invalid)
        PgpSignatureState.KEY_CHANGED -> "⚠️ " + getString(R.string.email_pgp_signature_key_changed)
        PgpSignatureState.NONE -> null
    }

    /** Built lazily: constructing it needs the pairing credential, which is a disk read — so this
     *  itself must only ever run off Main; see [attemptDecrypt]'s `Dispatchers.IO` hop. */
    private suspend fun encryptedReader(): EncryptedMessageReader? {
        val pairing = PushRuntime.graph(this).repository.pairingForAuthenticatedCall() ?: return null
        val deviceId = pairing.deviceId ?: return null
        val deviceSecret = pairing.deviceSecret ?: return null
        val client = PgpPayloadClient(callFactory = pinnedPairingCallFactory(this))
        return EncryptedMessageReader(
            // No wrapper here: AndroidVaultOpener.open() owns its own dispatching now — IO for the
            // Keystore/prefs read, Main only for the BiometricPrompt itself — so nothing in this
            // caller needs to hop for it. See VaultOpenerAndroid.kt.
            opener = AndroidVaultOpener(this@EmailDetailActivity),
            payloads = object : PayloadSource {
                override suspend fun fetch(mailbox: String, messageId: String) =
                    client.fetch(pairing.serverUrl, deviceId, deviceSecret, mailbox, messageId)
            },
        )
    }

    /**
     * Automatic when the key is already held, explicit when it is not.
     *
     * The prompt stays tied to a deliberate tap so that a dismissal is always a response to
     * something the user just did, rather than a sheet that ambushed a message they opened by
     * accident.
     *
     * [EncryptedMessageReader.read] is deliberately Android-free — no `withContext` anywhere inside
     * it — which makes dispatching it off Main this caller's job. Left on the default
     * `Dispatchers.Main.immediate` of [lifecycleScope], the happy path (key already held, automatic
     * decrypt) would run a Keystore-backed disk read, the full BouncyCastle decrypt/verify and the
     * MIME parse all on the UI thread — ANR-class on a large message. Only [encryptedReader]'s own
     * pairing lookup goes on `Dispatchers.IO` (it is disk I/O, not CPU work); the reader's `read`
     * itself goes on `Dispatchers.Default`, matching the CPU-bound work inside it. The one exception
     * is the biometric prompt: `AndroidVaultOpener.open()` owns that hop back to Main itself, so
     * nothing here has to arrange it.
     *
     * [decryptJob] guards against a second attempt landing mid-flight — see its KDoc.
     */
    private fun attemptDecrypt(mailbox: String, messageId: String, sender: String, unlockIfNeeded: Boolean) {
        if (decryptJob?.isActive == true) return
        btnDecryptHere.isEnabled = false
        btnRetryPayload.isEnabled = false
        decryptJob = lifecycleScope.launch {
            val reader = withContext(Dispatchers.IO) { encryptedReader() }
            if (reader == null) {
                renderReadOutcome(ReadOutcome.NotEnrolled)
                return@launch
            }
            val outcome = withContext(Dispatchers.Default) {
                reader.read(mailbox, messageId, sender, unlockIfNeeded)
            }
            renderReadOutcome(outcome)
        }
    }

    private fun renderReadOutcome(outcome: ReadOutcome) {
        if (isFinishing || isDestroyed) return
        btnDecryptHere.visibility = View.GONE
        btnDecryptHere.isEnabled = true
        btnRetryPayload.visibility = View.GONE
        btnRetryPayload.isEnabled = true

        when (outcome) {
            is ReadOutcome.Decrypted -> {
                // The one path that shows content. The body goes to the WebView and NOWHERE else:
                // not Room, and not fetchedBodyHtml, which feeds reply quoting into
                // ComposeDraftCache and on to POST /api/mail/draft — the server this message was
                // deliberately never readable by.
                lockedPlaceholder.visibility = View.GONE
                webView.visibility = View.VISIBLE
                val rawHtml = outcome.body.html
                    ?: "<pre>" + android.text.Html.escapeHtml(outcome.body.plain.orEmpty()) + "</pre>"
                // Routed through the same dark-theme override every other body gets — without it, a
                // sender who hardcodes their own colors (buildEmailBodyHtml's own KDoc: "virtually
                // all of them") renders black-on-black under a dark palette.
                val palette = getStoredThemePalette(this)
                val html = buildEmailBodyHtml(
                    rawHtml,
                    palette,
                    ibmPlexMonoFontFaceCss(this),
                    isDark = isDarkPalette(palette),
                )
                webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null)
                // The real subject from the encrypted part's protected headers, when the sender used
                // them — the outer envelope subject is only ever a placeholder for this path. This is
                // the entire point of protected headers; leaving it unrendered defeats them.
                outcome.body.protectedSubject?.takeIf { it.isNotBlank() }?.let { subjectView.text = it }
                // The verdict actually safe to display — see displaySignatureVerdict's KDoc for why
                // this can differ from outcome.signature itself.
                val verdict = displaySignatureVerdict(outcome)
                pgpSignatureState = verdict
                // Show the mailbox the verdict is ABOUT, not the header the sender wrote.
                //
                // `sender` and `resolvedSender` are separable by an attacker: a From whose display
                // name is `bob@example.com` and whose mailbox is `eve@evil.example` renders as
                // "bob@example.com <eve@evil.example>". The badge is computed against the resolved
                // mailbox, so putting the raw header beside it would let a badge earned by Eve's
                // key sit next to Bob's name. Wherever a verification verdict appears, the
                // resolved mailbox appears with it — and displaySignatureVerdict already guarantees
                // resolvedSender is non-blank whenever verdict is not NONE.
                if (verdict != PgpSignatureState.NONE) {
                    fromView.text = getString(R.string.email_from) + " " + outcome.resolvedSender
                }
                val notice = signatureNoticeFor(verdict)
                if (notice != null) {
                    pgpBar.visibility = View.VISIBLE
                    pgpText.text = notice
                    pgpText.visibility = View.VISIBLE
                } else {
                    pgpBar.visibility = View.GONE
                    pgpText.text = ""
                    pgpText.visibility = View.GONE
                }
                btnOpenInWebmail.visibility = View.GONE
            }
            ReadOutcome.NeedsUnlock -> {
                showLocked("")
                btnDecryptHere.visibility = View.VISIBLE
                btnOpenInWebmail.visibility = View.GONE
            }
            // Silent on purpose: the user dismissed a sheet they raised. A toast here would be
            // noise about their own action.
            ReadOutcome.Cancelled -> {
                showLocked("")
                btnDecryptHere.visibility = View.VISIBLE
                btnOpenInWebmail.visibility = View.GONE
            }
            ReadOutcome.NotEnrolled -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            ReadOutcome.NoSecureLockScreen -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            ReadOutcome.TooLarge -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            ReadOutcome.NotClientProtected -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            is ReadOutcome.UnsealFailed -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            is ReadOutcome.FetchFailed -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            // Terminal, unlike FetchFailed: the server answered, and its answer was that this
            // message carries no OpenPGP payload. Retrying cannot change that, so no Retry button —
            // offering one would invite the user to tap it forever.
            ReadOutcome.NoEncryptedContent -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
            is ReadOutcome.DecryptFailed -> {
                showLocked("")
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
        }
        // Routed through the pure decision below rather than set inline per-branch, so the one
        // outcome that must never offer Retry (NoEncryptedContent — see showsRetryButton's KDoc)
        // cannot drift out of sync with a JVM test that has no Android framework to exercise the
        // branches above directly.
        btnRetryPayload.visibility = if (showsRetryButton(outcome)) View.VISIBLE else View.GONE
    }

    /** The padlock and the webmail button always appear together: one says "not readable here",
     *  the other says "readable there" — except when [webmailUnavailable], where there is genuinely
     *  nowhere to send the user, and [R.string.email_pgp_no_webmail] is appended so the padlock does
     *  not sit next to a notice that dangles a webmail fallback with no button and no address on
     *  screen. */
    private fun showLocked(notice: String) {
        webView.visibility = View.GONE
        // Otherwise the decrypted plaintext DOM from an earlier Decrypted render lives on behind
        // the padlock, unloaded but still present.
        webView.loadUrl("about:blank")
        lockedPlaceholder.visibility = View.VISIBLE
        pgpBar.visibility = View.VISIBLE
        val body = if (webmailUnavailable) {
            if (notice.isBlank()) getString(R.string.email_pgp_no_webmail) else notice + "\n" + getString(R.string.email_pgp_no_webmail)
        } else {
            notice
        }
        // Prepended, not appended — same reasoning as renderPgpBar and the Decrypted branch above: a
        // signature that does not match the sender outranks a readability notice.
        val sig = signatureNoticeFor(pgpSignatureState)
        val bodyPart = body.takeIf { it.isNotBlank() }
        pgpText.text = listOfNotNull(sig, bodyPart).joinToString("\n\n")
        pgpText.visibility = if (pgpText.text.isNullOrBlank()) View.GONE else View.VISIBLE
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
                when (action) {
                    // Deliberately NOT cached for forwarding on this path. rememberForForwarding
                    // base64-encodes the plaintext into an immutable String that lives for the life
                    // of this Activity — and, once forwarded, in the process-scoped
                    // ForwardAttachmentHandoff. A String cannot be zeroed. That silently undid the
                    // entire point of EphemeralAttachmentBytes, which goes to some trouble to
                    // Arrays.fill(bytes, 0) on a timer, and it did so under Hostile Location
                    // Protection specifically — the mode whose contract is that attachment
                    // plaintext never persists anywhere. forwardMessage() already re-fetches
                    // anything it does not have, so the cost is one extra download on a forward.
                    com.urlxl.mail.security.AttachmentAction.VIEW_EPHEMERAL -> viewAttachmentEphemerally(downloaded)
                    com.urlxl.mail.security.AttachmentAction.SAVE_TO_DOWNLOADS -> {
                        rememberForForwarding(info.index, downloaded)
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
        val mimeType = safeMimeType(downloaded.mimeType)
        // Null when the held-plaintext ceiling is reached — say so rather than launching a chooser
        // for a URI that will fail to open. See EphemeralAttachmentBytes.register.
        val uri = com.urlxl.mail.security.EphemeralAttachmentBytes.register(downloaded.bytes, mimeType)
            ?: run {
                Toast.makeText(this, R.string.attachment_too_many_open, Toast.LENGTH_LONG).show()
                return
            }
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

    /**
     * Writes bytes into the shared Downloads collection via MediaStore (no storage permission
     * needed on the app's minSdk 31). Returns false if the insert or stream write fails.
     *
     * Name and type are sanitised on the way in, exactly as [viewAttachmentEphemerally] does.
     * Both come from the sender's `Content-Disposition`/`Content-Type`, which the relay passes
     * through unfiltered — and this is the branch taken when Hostile Location Protection is *off*,
     * i.e. by default, so it was the unhardened path that nearly everyone uses.
     */
    private fun saveToDownloads(name: String, mimeType: String, bytes: ByteArray): Boolean {
        val resolver = contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, safeFileName(name))
            put(MediaStore.Downloads.MIME_TYPE, safeMimeType(mimeType))
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
        }
        return runCatching {
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return false
            resolver.openOutputStream(uri)?.use { it.write(bytes) } ?: return false
            // Recorded so a later security wipe can delete it. This file is outside the app
            // sandbox, so nothing the wipe deletes reaches it — and the screen after a wipe tells
            // the user their local data has been erased.
            com.urlxl.mail.security.DownloadedAttachmentLedger.record(this, uri)
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
     *  scheme and the user gesture; see [SAFE_LINK_SCHEMES].
     *
     *  Deliberately NOT a Custom Tab, unlike the webmail handoff in renderPgpBar. A Custom Tab
     *  renders inside this app's task wearing this app's toolbar colour, so a page opened in one
     *  reads to the user as part of the app. That is the right frame for the user's own webmail
     *  and precisely the wrong one for a URL chosen by whoever sent the email. Sender-controlled
     *  links go to a separate browser app, where the address bar and the app switch are the
     *  cues that this is somewhere else. */
    private fun openExternally(uri: android.net.Uri) {
        val intent = Intent(Intent.ACTION_VIEW, uri)
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
            .onFailure { Toast.makeText(this, R.string.email_link_no_handler, Toast.LENGTH_SHORT).show() }
    }

    /**
     * The quoted original, as HTML, sanitized for the compose editor.
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
     *
     * Both quote builders go through here so the sanitize step cannot be forgotten on one of them.
     * The editor is a JavaScript-enabled WebView with a bound `@JavascriptInterface` and its
     * `setHtml` assigns to `innerHTML`, so an `onerror` attribute in a quoted message would execute
     * with the user's outgoing mail in reach — see [com.urlxl.mail.mail.QuotedHtmlSanitizer].
     */
    /**
     * Sanitizes the quoted original off the UI thread, and refuses to try past a size bound.
     *
     * Both properties are load-bearing, and neither was present. `Jsoup.clean` costs time quadratic
     * in the sender's chosen nesting depth: measured against this exact function, 10k nested `<div>`
     * (50 KB) took 122 ms, 40k took 2.2 s, 80k (400 KB) took 12.7 s and 200k (1 MB) took 156 s, with
     * the output amplified up to 14.6x. This ran straight from the Reply/Reply-All/Forward click
     * listeners with no cap at all, so a message whose body is `"<div>".repeat(80000)` plus "please
     * reply to confirm" reliably ANR'd the app on a single natural tap, repeatable with every
     * message. The body is bounded only by the 32 MB response cap, so the tail is unbounded too.
     *
     * Run-2 found and fixed this same class in this same file — two quadratic regexes, closed with a
     * bounded pattern and a 512 KB cap — and the new sanitizer reintroduced it on the *main* thread.
     * The sibling jsoup call in this file, [stripImportant], was already on [ioExecutor]; now both
     * are. Past the cap the quote degrades to the escaped preview, which is the same fallback this
     * already used when the body is genuinely unavailable.
     */
    private fun quotedBodyHtmlAsync(preview: String, then: (String) -> Unit) {
        val body = fetchedBodyHtml?.takeIf { it.isNotBlank() }
        if (body == null || body.length > REMOTE_IMAGE_SCAN_MAX_LENGTH) {
            then(TextUtils.htmlEncode(preview))
            return
        }
        ioExecutor.execute {
            val sanitized = runCatching { QuotedHtmlSanitizer.sanitize(body) }
                .getOrElse { TextUtils.htmlEncode(preview) }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                then(sanitized)
            }
        }
    }

    private fun quoteForReply(sender: String, quoted: String): String =
        "<br><br><div>${TextUtils.htmlEncode(sender)} wrote:</div>" +
            "<blockquote style=\"margin:0 0 0 0.8ex;border-left:1px solid #ccc;padding-left:1ex\">" +
            quoted +
            "</blockquote>"

    private fun quoteForForward(sender: String, subject: String, quoted: String): String =
        "<br><br><div>---------- Forwarded message ----------</div>" +
            "<div>From: ${TextUtils.htmlEncode(sender)}</div>" +
            "<div>Subject: ${TextUtils.htmlEncode(subject)}</div><br>" +
            quoted

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

        /** Bodies past this size skip the remote-content scan entirely and assume none. */
        private const val REMOTE_IMAGE_SCAN_MAX_LENGTH = 512 * 1024

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

/**
 * Whether [outcome] should offer a Retry button.
 *
 * True only for [ReadOutcome.FetchFailed] — a transport failure a second attempt might not repeat.
 * [ReadOutcome.NoEncryptedContent] looks similar at a glance (both leave the message unread) but is
 * terminal: the server answered, and its answer was that this message carries no OpenPGP payload,
 * so retrying cannot change it. Offering Retry there would invite the user to tap it forever.
 *
 * Pulled out as its own pure function — rather than left inline in [EmailDetailActivity]'s
 * `renderReadOutcome` `when` — so this one decision has a JVM test with no Android framework
 * involved, on a file where `isReturnDefaultValues = true` makes most other UI logic untestable.
 */
internal fun showsRetryButton(outcome: ReadOutcome): Boolean = outcome is ReadOutcome.FetchFailed

/**
 * The signature verdict actually safe to display for [outcome].
 *
 * [ReadOutcome.Decrypted.signature] can be non-[PgpSignatureState.NONE] — e.g.
 * [PgpSignatureState.SIGNER_UNKNOWN] — even when [ReadOutcome.Decrypted.resolvedSender] is blank:
 * [com.urlxl.mail.pgp.PgpPayloadResult.resolvedSender]'s own KDoc documents this ("empty when the
 * server could not resolve one, e.g. a multi-mailbox From"), and a multi-mailbox `From` is exactly
 * the attacker-separable shape the resolved-vs-raw-sender display rule exists for in the first
 * place. Showing a verdict with no resolved mailbox to pin it to lets that verdict read as being
 * about whatever raw sender text the screen still has on it — so with no resolved mailbox to
 * display, this returns [PgpSignatureState.NONE]: there is nothing safe to say.
 *
 * A security rule, not a cosmetic one, which is why it is pulled out as its own pure, tested
 * function rather than left as the compound boolean it replaced.
 */
internal fun displaySignatureVerdict(outcome: ReadOutcome.Decrypted): PgpSignatureState =
    outcome.signature.takeIf { outcome.resolvedSender.isNotBlank() } ?: PgpSignatureState.NONE

/**
 * Whether Reply, Reply-All or Forward may be offered for a message in [state].
 *
 * False only for [PgpMessageState.CLIENT_PROTECTED] — see [EmailDetailActivity.applyReplyForwardAvailability]
 * for why that has to hold even once the message is decrypted on screen: `POST /api/mail/draft`
 * uploads to the server, so quoting a decrypted body into a reply would hand the server plaintext
 * this mode exists to keep from it, and there is no encrypted send path in the app to make that
 * safe.
 *
 * Pulled out as its own pure function for the same reason as [showsRetryButton] above: a JVM test
 * with no Android framework, on a file where `isReturnDefaultValues = true` makes the Activity's
 * own view-toggling logic untestable.
 */
internal fun mayReplyOrForward(state: PgpMessageState): Boolean = state != PgpMessageState.CLIENT_PROTECTED

/**
 * The [PgpMessageState] Reply/Reply-All/Forward should assume for [pgpEncrypted] before
 * `renderBody`'s background fetch — which may make a network round trip for an uncached message,
 * and may never complete at all if it throws — can report the real state.
 *
 * Fails closed: an encrypted message defaults to [PgpMessageState.CLIENT_PROTECTED], the one state
 * [mayReplyOrForward] refuses, rather than [PgpMessageState.NONE]. The alternative — assume
 * replyable until told otherwise — leaves the buttons live for the entire fetch on exactly the
 * messages this task exists to protect, and forever if the fetch throws. An unencrypted message
 * defaults to [PgpMessageState.NONE] since it was never going to become [PgpMessageState.CLIENT_PROTECTED]
 * regardless of how the fetch turns out, so there's no reason to hold it hostage to the same wait.
 *
 * Pulled out as its own pure function, rather than left as the ternary it replaced inline in
 * `onCreate`, so this specific fail-closed default has a JVM test independent of the Activity that
 * reads it — `EmailDetailActivity` itself can't be instantiated in this module's plain JUnit
 * tests (no Robolectric; see the other Android-framework-free notes throughout this file's test
 * class).
 */
internal fun initialReplyForwardState(pgpEncrypted: Boolean): PgpMessageState =
    if (pgpEncrypted) PgpMessageState.CLIENT_PROTECTED else PgpMessageState.NONE

/**
 * The sender's filename, reduced to something safe to hand MediaStore.
 *
 * Drops path separators (so nothing can steer the write out of `Downloads/`), drops every character
 * that is not plainly part of a filename — which also removes the NUL and control bytes used to
 * make a name read as one extension and resolve as another — and bounds the length.
 */
internal fun safeFileName(raw: String): String =
    raw.substringAfterLast('/')
        .substringAfterLast('\\')
        .filter { it.isLetterOrDigit() || it in "._- ()[]" }
        .trim()
        .trimStart('.')
        .take(120)
        .ifBlank { "attachment" }

/**
 * MIME types this app will hand to another app as-declared. Anything else becomes
 * `application/octet-stream`, which every file handler competes for.
 *
 * The type comes from the sender's `Content-Type`, which the relay passes through unfiltered. An
 * obscure type like `application/vnd.kypost-x` lets a co-installed app guarantee itself
 * sole-resolver status for the attachment — so it applies on both the ephemeral-view path and the
 * save-to-Downloads path, not just the one that skips disk.
 */
private val VIEWABLE_MIME_TYPES = setOf(
    "application/pdf",
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic",
    "text/plain",
    "audio/mpeg", "audio/mp4", "audio/ogg",
    "video/mp4", "video/webm",
)

internal fun safeMimeType(raw: String): String =
    raw.substringBefore(';').trim().lowercase()
        .takeIf { it in VIEWABLE_MIME_TYPES }
        ?: "application/octet-stream"

// A CSS comment produces zero tokens during tokenization (CSS Syntax §4) and is fully transparent
// between any two other tokens — including between `!` and `important` — so it has to be removed
// before the token check rather than matched around.
private val CSS_COMMENT = Regex("""/\*[^*]*\*+(?:[^/*][^*]*\*+)*/""")

// A CSS escape sequence is a backslash followed by 1-6 hex digits and an optional whitespace
// terminator (CSS Syntax §4.3.7), so a sender can spell any letter of "important" as an escape
// (`!\49 mportant` decodes to `!Important`).
private val CSS_ESCAPE = Regex("""\\([0-9a-fA-F]{1,6})\s?""")

private val BANG_CANDIDATE = Regex("""\s*!((?:\\[0-9a-fA-F]{1,6}\s?|[A-Za-z\s]){1,24})""")

/**
 * Decodes CSS escape sequences, leaving anything that is not a valid code point as literal text.
 *
 * [CSS_ESCAPE] matches up to six hex digits, which reaches 0xFFFFFF — past the 0x10FFFF ceiling of
 * the Unicode codespace — and `Character.toChars` throws on those. CSS treats an out-of-range escape
 * as a parse error rendering as U+FFFD, so it can never spell a letter of "important" either way.
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

/**
 * Removes every `!important` from one CSS declaration block or stylesheet body.
 *
 * Tolerant of the two spec-legal ways a sender can split the token to dodge a plain text search: a
 * CSS comment inserted anywhere, and any letter written as an escape sequence.
 */
internal fun stripImportantFromCss(css: String): String =
    BANG_CANDIDATE.replace(css.replace(CSS_COMMENT, "")) { match ->
        if (decodeCssEscapes(match.groupValues[1]).trim().equals("important", ignoreCase = true)) {
            ""
        } else {
            match.value
        }
    }

/**
 * Strips every `!important` the sender's markup can bring — see [buildEmailBodyHtml] for why that
 * is what actually closes the dark-mode override gap.
 *
 * Parsed with jsoup rather than pattern-matched over the raw body. The previous version was a
 * text-level regex sweep across the whole message, justified by "this app has no HTML parser
 * dependency" — which stopped being true when jsoup was added for [com.urlxl.mail.mail.QuotedHtmlSanitizer].
 * Doing it structurally means the token patterns only ever run over a single `style` attribute or
 * `<style>` block, so the catastrophic-backtracking cases that needed a bounded whitespace run and a
 * 512 KB skip-the-whole-thing cap are no longer reachable from a message body at all — and CSS in
 * places CSS cannot apply (text, comments, attribute values) is no longer rewritten.
 *
 * Returns [html] byte-identical when nothing needed changing, so an unstyled message is not
 * re-serialised through the parser for no reason.
 */
internal fun stripImportant(html: String): String {
    if (html.isBlank()) return html
    val doc = runCatching { org.jsoup.Jsoup.parseBodyFragment(html) }.getOrNull() ?: return html
    doc.outputSettings().prettyPrint(false)

    var changed = false
    doc.select("[style]").forEach { element ->
        val original = element.attr("style")
        val cleaned = stripImportantFromCss(original)
        if (cleaned != original) {
            element.attr("style", cleaned)
            changed = true
        }
    }
    doc.select("style").forEach { element ->
        val original = element.data()
        val cleaned = stripImportantFromCss(original)
        if (cleaned != original) {
            element.empty()
            element.appendChild(org.jsoup.nodes.DataNode(cleaned))
            changed = true
        }
    }
    return if (changed) doc.body().html() else html
}
