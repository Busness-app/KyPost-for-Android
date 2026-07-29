package com.urlxl.mail

import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.TextUtils
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.infomaniak.lib.richhtmleditor.RichHtmlEditorWebView
import com.urlxl.mail.contacts.AddressBookSheet
import com.urlxl.mail.contacts.RecipientCandidate
import com.urlxl.mail.contacts.RecipientField
import com.urlxl.mail.contacts.toRecipientCandidateOrNull
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.mail.MailDraft
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.MailRuntime
import com.urlxl.mail.mail.OutgoingAttachment
import com.urlxl.mail.mail.userFacingMessage
import com.urlxl.mail.pgp.PgpComposeState
import com.urlxl.mail.pgp.webmailDraftsUrl
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.Executors
import com.urlxl.mail.security.LockedActivity

class ComposeActivity : LockedActivity() {

    private lateinit var toInput: RecipientInputView
    private lateinit var ccInput: RecipientInputView
    private lateinit var bccInput: RecipientInputView
    private lateinit var subjectField: EditText
    private lateinit var bodyEditor: RichHtmlEditorWebView
    private lateinit var bodyPlaceholder: android.view.View
    private lateinit var attachButton: Chip
    private lateinit var attachmentChips: ChipGroup
    private lateinit var boldChip: Chip
    private lateinit var italicChip: Chip
    private lateinit var underlineChip: Chip
    private lateinit var linkChip: Chip
    private lateinit var detailsCard: android.view.View
    private lateinit var messageCard: android.view.View
    private lateinit var detailsDividers: List<android.view.View>
    private lateinit var messageDivider: android.view.View
    private lateinit var rootView: android.view.View
    private lateinit var pgpChips: ChipGroup
    private lateinit var encryptChip: Chip
    private lateinit var signChip: Chip
    private lateinit var webmailChip: Chip
    private lateinit var keylessWarning: android.widget.TextView
    private val pgpController by lazy { ComposePgpController.from(this) }
    private var sendMenuItem: MenuItem? = null
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val attachments = mutableListOf<OutgoingAttachment>()

    /** The in-flight preflight check, if any. Cancelled whenever a newer one supersedes it (a
     *  recipient change while Encrypt is checked) or Encrypt is switched off, so a late result
     *  can never re-show the "no key on file" warning after the toggle has already gone off. */
    private var preflightJob: Job? = null

    /** The draft as it was actually sent, kept so the post-409 re-send reuses it byte-for-byte
     *  with only allowPickupFallback flipped. Re-exporting the editor HTML or re-encoding the
     *  attachments could produce a subtly different message. */
    private var sentDraft: MailDraft? = null

    /** Set once the relay confirms delivery, so [onStop] does not re-cache a message that has
     *  already been sent — which would otherwise reappear as a "restored draft" next time. */
    private var sendSucceeded = false

    /** The currently shown pickup-fallback/webmail-handoff dialog, if any — dismissed in
     *  [onDestroy] so it does not outlive the Activity's window. */
    private var activeDialog: AlertDialog? = null

    private val pickAttachments = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris -> if (!uris.isNullOrEmpty()) addAttachments(uris) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return
        setContentView(R.layout.activity_compose)
        applyThemeToActivity(this)

        rootView = findViewById(R.id.composeRoot)
        applyTopInsetWithHeader(this, rootView)

        setTitle(R.string.compose_email)

        subjectField = findViewById(R.id.composeSubjectField)
        bodyEditor = findViewById(R.id.composeBodyEditor)
        // The editor ships with JavaScript on and a bound @JavascriptInterface, and it quotes
        // sender-authored markup. QuotedHtmlSanitizer is the primary control; these are the
        // independent second layer, and they close the leak that needs no script at all: without
        // blockNetworkLoads, merely pressing Reply or Forward fetched every remote image, iframe
        // and stylesheet the sender embedded, defeating the reader's "Show images" opt-in.
        //
        // Safe for the editor itself: its chrome is loaded from an inlined template, not over the
        // network, and on minSdk 31 file:///android_asset stays reachable regardless of
        // allowFileAccess.
        bodyEditor.settings.apply {
            blockNetworkLoads = true
            allowContentAccess = false
            allowFileAccess = false
        }
        bodyPlaceholder = findViewById(R.id.composeBodyPlaceholder)
        attachButton = findViewById(R.id.composeAttachButton)
        attachmentChips = findViewById(R.id.composeAttachmentsCard)
        boldChip = findViewById(R.id.composeBold)
        italicChip = findViewById(R.id.composeItalic)
        underlineChip = findViewById(R.id.composeUnderline)
        linkChip = findViewById(R.id.composeLink)
        detailsCard = findViewById(R.id.composeDetailsCard)
        messageCard = findViewById(R.id.composeMessageCard)
        detailsDividers = listOf(
            findViewById(R.id.composeDetailsDivider1),
            findViewById(R.id.composeDetailsDivider2),
            findViewById(R.id.composeDetailsDivider3),
        )
        messageDivider = findViewById(R.id.composeMessageDivider)

        pgpChips = findViewById(R.id.composePgpChips)
        encryptChip = findViewById(R.id.composeEncryptChip)
        signChip = findViewById(R.id.composeSignChip)
        webmailChip = findViewById(R.id.composeWebmailChip)
        keylessWarning = findViewById(R.id.composeKeylessWarning)
        applyWarningCalloutTheme(this, keylessWarning)

        lifecycleScope.launch { applyPgpComposeState(pgpController.composeState()) }

        toInput = findViewById(R.id.composeToInput)
        ccInput = findViewById(R.id.composeCcInput)
        bccInput = findViewById(R.id.composeBccInput)
        toInput.setLabel(getString(R.string.email_to))
        ccInput.setLabel(getString(R.string.email_cc))
        bccInput.setLabel(getString(R.string.email_bcc))

        val contactDao = DataRuntime.graph(this).database.contactDao()
        val searchContacts: suspend (String) -> List<RecipientCandidate> = { query ->
            contactDao.search(query).mapNotNull { it.toRecipientCandidateOrNull() }
        }
        toInput.configure(searchContacts, onOpenAddressBook = ::openAddressBook)
        ccInput.configure(searchContacts)
        bccInput.configure(searchContacts)

        // Re-run the preflight whenever the committed recipient set changes, but only while
        // Encrypt is on — otherwise toggling Encrypt before any recipient is entered means
        // splitAddresses() sees an empty list, the initial check short-circuits, and the warning
        // never appears again no matter how many keyless addresses are added afterward.
        val onRecipientsChanged = { if (encryptChip.isChecked) runPreflight() }
        toInput.onRecipientsChanged = onRecipientsChanged
        ccInput.onRecipientsChanged = onRecipientsChanged
        bccInput.onRecipientsChanged = onRecipientsChanged

        // A draft the app lock destroyed on a previous entry wins over the intent's prefill: the
        // user typed it, and it is strictly newer than whatever Reply/Forward put there.
        val restored = ComposeDraftCache.take()
        if (restored != null) {
            subjectField.setText(restored.subject)
            toInput.setInitialRecipients(restored.to)
            ccInput.setInitialRecipients(restored.cc)
            bccInput.setInitialRecipients(restored.bcc)
            attachments.addAll(restored.attachments)
            renderAttachmentChips()
            bodyEditor.setHtml(restored.bodyHtml)
            // The restored draft already carries its own attachments; a handoff left over from an
            // abandoned forward must not be merged into it.
            ForwardAttachmentHandoff.clear()
            Toast.makeText(this, R.string.compose_draft_restored, Toast.LENGTH_SHORT).show()
        } else {
            subjectField.setText(intent.getStringExtra(EXTRA_SUBJECT).orEmpty())
            toInput.setInitialRecipients(intent.getStringExtra(EXTRA_TO).orEmpty())
            // EXTRA_BODY_HTML carries a real HTML quote (Reply/Forward of an HTML message);
            // EXTRA_BODY is plain text and still has to be escaped before it reaches the editor.
            val prefillHtml = intent.getStringExtra(EXTRA_BODY_HTML).orEmpty()
            bodyEditor.setHtml(
                prefillHtml.ifBlank { plainTextToHtml(intent.getStringExtra(EXTRA_BODY).orEmpty()) },
            )
            // A forward's attachments, handed over out-of-band because they are far too large for
            // an Intent extra — see [ForwardAttachmentHandoff].
            val forwarded = ForwardAttachmentHandoff.take()
            if (forwarded.isNotEmpty()) {
                attachments.addAll(forwarded)
                renderAttachmentChips()
            }
        }

        boldChip.setOnClickListener { bodyEditor.toggleBold() }
        italicChip.setOnClickListener { bodyEditor.toggleItalic() }
        underlineChip.setOnClickListener { bodyEditor.toggleUnderline() }
        linkChip.setOnClickListener {
            if (linkChip.isChecked) {
                bodyEditor.unlink()
            } else {
                showCreateLinkDialog()
            }
        }

        lifecycleScope.launch {
            bodyEditor.editorStatusesFlow.collect { statuses ->
                boldChip.isChecked = statuses.isBold
                italicChip.isChecked = statuses.isItalic
                underlineChip.isChecked = statuses.isUnderlined
                linkChip.isChecked = statuses.isLinkSelected
            }
        }
        bodyEditor.isEmptyFlow
            .onEach { isEmpty -> bodyPlaceholder.visibility = if (isEmpty != false) android.view.View.VISIBLE else android.view.View.GONE }
            .launchIn(lifecycleScope)

        attachButton.setOnClickListener { pickAttachments.launch(arrayOf("*/*")) }
        applyToolbarChipsTheme()
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyToolbarChipsTheme()
        applySendMenuItemTheme()
        applyEditorThemeCss()
        toInput.applyTheme()
        ccInput.applyTheme()
        bccInput.applyTheme()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        if (redirectedToUnlock) return false
        val item = menu.add(0, MENU_SEND, 0, R.string.compose_send)
        item.setIcon(R.drawable.ic_send)
        item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        sendMenuItem = item
        applySendMenuItemTheme()
        return super.onCreateOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_SEND -> {
                sendEmail()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun applySendMenuItemTheme() {
        val accent = Color.parseColor(getStoredThemePalette(this).accent)
        sendMenuItem?.icon?.mutate()?.setTint(readableOn(accent))
    }

    private fun openAddressBook() {
        AddressBookSheet { candidate, field ->
            val target = when (field) {
                RecipientField.TO -> toInput
                RecipientField.CC -> ccInput
                RecipientField.BCC -> bccInput
            }
            target.addRecipient(candidate.email, candidate.name)
        }.show(supportFragmentManager, AddressBookSheet.TAG)
    }

    private fun applyToolbarChipsTheme() {
        listOf(boldChip, italicChip, underlineChip, linkChip, attachButton, encryptChip, signChip, webmailChip).forEach {
            applyPillChipTheme(this, it)
        }
        // applyThemeToViewTree paints every ViewGroup (root included) flat `panel`-colored by
        // default, so root and the cards below would otherwise be indistinguishable. Repaint the
        // root `bg`-colored (mirrors InboxActivity's recyclerView.setBackgroundColor(bg)) so the
        // rounded `panel` cards actually pop against it instead of blending in.
        rootView.setBackgroundColor(Color.parseColor(getStoredThemePalette(this).bg))
        // Rounded panel cards behind each section — shared STYLE_GUIDE.md §3 Card/panel radius,
        // same applyPanelBackground precedent as Inbox's keyword-chip bar.
        applyPanelBackground(this, detailsCard)
        applyPanelBackground(this, messageCard)
        applyPanelBackground(this, attachmentChips)
        val line = Color.parseColor(getStoredThemePalette(this).line)
        detailsDividers.forEach { it.setBackgroundColor(line) }
        messageDivider.setBackgroundColor(line)
    }

    /** Views only — the rule itself is [com.urlxl.mail.pgp.pgpComposeStateOf], unit-tested. */
    private fun applyPgpComposeState(state: PgpComposeState) {
        encryptChip.visibility = if (state.canEncrypt) View.VISIBLE else View.GONE
        signChip.visibility = if (state.canSign) View.VISIBLE else View.GONE
        webmailChip.visibility = if (state.handoffToWebmail) View.VISIBLE else View.GONE
        pgpChips.visibility =
            if (state.canEncrypt || state.canSign || state.handoffToWebmail) View.VISIBLE else View.GONE

        encryptChip.setOnCheckedChangeListener { _, checked ->
            if (checked) {
                runPreflight()
            } else {
                // Cancel rather than let a stale result land after the toggle has gone off — a
                // superseded preflight must never overwrite the newer (in this case: hidden) state.
                preflightJob?.cancel()
                hideKeylessWarning()
            }
        }
        webmailChip.setOnClickListener { handOffToWebmail() }
    }

    /** Runs when Encrypt is switched on, and again on every committed recipient change while it
     *  stays on (see the onRecipientsChanged wiring in onCreate). Not debounced per keystroke:
     *  recipients are committed as chips by RecipientInputView rather than typed continuously, so
     *  this fires on a settled address list, never mid-keystroke.
     *
     *  Cancels any still-running preflight before starting a new one, so a recipient added a
     *  moment after a slow check started can't have its result clobbered by the earlier one
     *  landing late. */
    private fun runPreflight() {
        val addresses = splitAddresses(
            toInput.commaJoinedRecipients(),
            ccInput.commaJoinedRecipients(),
            bccInput.commaJoinedRecipients(),
        )
        preflightJob?.cancel()
        preflightJob = lifecycleScope.launch {
            val keyless = pgpController.keylessRecipients(addresses)
            if (keyless.isEmpty()) {
                hideKeylessWarning()
            } else {
                keylessWarning.text =
                    getString(R.string.compose_pgp_no_key_on_file, keyless.joinToString(", "))
                keylessWarning.visibility = View.VISIBLE
            }
        }
    }

    private fun hideKeylessWarning() {
        keylessWarning.visibility = View.GONE
    }

    /** Injects the active palette into the editor's WebView content so it doesn't render as a
     *  fixed light/dark WebView default regardless of the in-app theme. Passing the same [id] on
     *  every call replaces the previous tag rather than accumulating one per theme switch.
     *
     *  Also sets a floor on the document's own height: the editor watches
     *  `document.documentElement`'s resize and reports that height back to Android, which then
     *  becomes the WebView's *explicit* height (see the library's define_listeners.js /
     *  updateWebViewHeight) — overriding any Android-side match_parent/minHeight. Without a
     *  min-height here, an empty document reports only ~1rem, and the WebView shrinks to a single
     *  line no matter how much space its parent layout gives it. */
    private fun applyEditorThemeCss() {
        val palette = getStoredThemePalette(this)
        val css = """
            html, body {
                min-height: 500px;
            }
            body {
                background-color: ${palette.bg};
                color: ${palette.inkStrong};
                font-family: sans-serif;
                font-size: 16px;
            }
            a { color: ${palette.accent}; }
        """.trimIndent()
        bodyEditor.addCss(css, id = "kypost-compose-theme")
    }

    private fun showCreateLinkDialog() {
        val padding = (16 * resources.displayMetrics.density).toInt()
        val urlField = EditText(this).apply { hint = getString(R.string.compose_link_dialog_url_hint) }
        val textField = EditText(this).apply { hint = getString(R.string.compose_link_dialog_text_hint) }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, 0)
            addView(urlField)
            addView(textField)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_link_dialog_title)
            .setView(container)
            .setPositiveButton(R.string.compose_link_dialog_add) { _, _ ->
                val url = urlField.text.toString().trim()
                if (url.isNotBlank()) bodyEditor.createLink(textField.text.toString().trim(), url)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun plainTextToHtml(text: String): String {
        if (text.isEmpty()) return ""
        return TextUtils.htmlEncode(text).replace("\n", "<br>")
    }

    /**
     * Adds the picked documents, one at a time.
     *
     * Sequential rather than a `forEach` of independent jobs: each one is checked against the
     * remaining budget, and concurrent checks would all see the same "before" total and every one
     * of them would pass.
     */
    private fun addAttachments(uris: List<Uri>) {
        lifecycleScope.launch {
            for (uri in uris) {
                if (isFinishing || isDestroyed) return@launch
                addAttachment(uri)
            }
        }
    }

    /**
     * Reads one picked document on [Dispatchers.IO], enforces the 25 MB total cap (matching the
     * backend) **before** the bytes are in the heap, and renders a removable chip.
     *
     * Three things were wrong here. `OpenableColumns.SIZE` was read and then never used — the cap
     * was applied to `bytes.size`, i.e. after `readBytes()` had already materialised the entire
     * document, so picking a multi-gigabyte file from a cloud provider was an `OutOfMemoryError`
     * (which `runCatching` does not catch, so: a hard crash with an unsent message in flight, before
     * `onStop` could cache the draft). The read, the 33 MB base64 `String` and the whole thing again
     * for every file in a multi-select all ran on the main thread, from the picker callback — an ANR
     * on any real attachment. And the KDoc said "off the UI thread", which is where it was.
     *
     * The declared size is a hint, not a guarantee — a provider may under-report or omit it — so the
     * stream read is bounded too, and refuses rather than truncating. Same contract as
     * [com.urlxl.mail.mail.readBounded] on the inbound side, for the same reason: a silently
     * truncated attachment is worse than a refused one.
     */
    private suspend fun addAttachment(uri: Uri) {
        val resolver = contentResolver
        val budget = MAX_ATTACHMENT_BYTES - attachments.sumOf { it.size.toLong() }

        val picked = withContext(Dispatchers.IO) {
            var name = "attachment"
            var declaredSize = -1L
            runCatching {
                resolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (nameIdx >= 0 && !cursor.isNull(nameIdx)) name = cursor.getString(nameIdx)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) declaredSize = cursor.getLong(sizeIdx)
                    }
                }
            }
            // Refuse on the advertised size first, so an oversized file is never opened at all.
            if (declaredSize > budget) return@withContext PickedAttachment.TooLarge(name)

            val bytes = try {
                resolver.openInputStream(uri)?.use { readAtMost(it, budget, declaredSize) }
            } catch (e: AttachmentTooLargeException) {
                // The provider under-reported, or omitted, OpenableColumns.SIZE.
                android.util.Log.i(TAG, "Picked attachment exceeded the remaining budget", e)
                return@withContext PickedAttachment.TooLarge(name)
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Could not read the picked attachment", e)
                return@withContext PickedAttachment.Unreadable(name)
            } ?: return@withContext PickedAttachment.Unreadable(name)

            PickedAttachment.Ready(
                OutgoingAttachment(
                    name = name,
                    mimeType = resolver.getType(uri) ?: "application/octet-stream",
                    dataBase64 = Base64.encodeToString(bytes, Base64.NO_WRAP),
                    size = bytes.size,
                ),
            )
        }

        if (isFinishing || isDestroyed) return
        when (picked) {
            is PickedAttachment.Ready -> {
                attachments.add(picked.attachment)
                renderAttachmentChips()
            }
            is PickedAttachment.TooLarge ->
                Toast.makeText(this, getString(R.string.compose_attachments_too_large), Toast.LENGTH_LONG).show()
            is PickedAttachment.Unreadable ->
                Toast.makeText(this, getString(R.string.compose_attachment_unreadable, picked.name), Toast.LENGTH_SHORT).show()
        }
    }

    /** Outcome of reading one picked document — named rather than a nullable pair so the three
     *  cases stay distinguishable at the call site. */
    private sealed class PickedAttachment {
        data class Ready(val attachment: OutgoingAttachment) : PickedAttachment()
        data class TooLarge(val name: String) : PickedAttachment()
        data class Unreadable(val name: String) : PickedAttachment()
    }

    private fun renderAttachmentChips() {
        attachmentChips.removeAllViews()
        attachmentChips.visibility = if (attachments.isEmpty()) android.view.View.GONE else android.view.View.VISIBLE
        attachments.forEach { attachment ->
            val chip = Chip(this).apply {
                text = attachment.name
                isCloseIconVisible = true
                setOnCloseIconClickListener {
                    attachments.remove(attachment)
                    renderAttachmentChips()
                }
            }
            applyPillChipTheme(this, chip)
            attachmentChips.addView(chip)
        }
    }

    private fun sendEmail() {
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString().trim()
        val isBodyEmpty = bodyEditor.isEmptyFlow.value != false

        if (to.isBlank() || subject.isBlank() || isBodyEmpty) {
            Toast.makeText(this, R.string.compose_fill_all_fields, Toast.LENGTH_SHORT).show()
            return
        }

        sendMenuItem?.isEnabled = false

        bodyEditor.exportHtml { html ->
            // exportHtml's callback runs on the main looper and can still fire after onDestroy has
            // called ioExecutor.shutdownNow() (e.g. app lock finishing this screen while the
            // export was pending) — dispatchSend below would then hit a shut-down executor and
            // throw RejectedExecutionException.
            if (isFinishing || isDestroyed) return@exportHtml
            val draft = MailDraft(
                to = to, cc = cc, bcc = bcc, subject = subject, body = html, mode = "html",
                attachments = attachments.toList(),
                sign = signChip.isChecked && signChip.visibility == View.VISIBLE,
                encrypt = encryptChip.isChecked && encryptChip.visibility == View.VISIBLE,
                // Never on for a first attempt. Only the post-409 re-send sets it, and only after
                // the user confirmed the dialog naming the addresses.
                allowPickupFallback = false,
            )
            sentDraft = draft
            dispatchSend(draft)
        }
    }

    /** Shared by the first attempt and the confirmed re-send, so the re-send cannot drift. */
    private fun dispatchSend(draft: MailDraft) {
        ioExecutor.execute {
            val outcome = MailRuntime.graph(this).repository.send(draft)
            runOnUiThread {
                // The round trip above can outlive the Activity: LockedActivity.onStart finishes
                // this screen outright if the app lock engages while a send is in flight, and
                // Activity.runOnUiThread still runs its Runnable after finish(). Building an
                // AlertDialog on a finishing/destroyed Activity throws BadTokenException (or, on a
                // merely-finishing one, succeeds and leaks the window) — bail before either dialog
                // branch runs.
                if (isFinishing || isDestroyed) return@runOnUiThread
                when (outcome) {
                    is MailOutcome.Success -> {
                        val warning = outcome.value.warning
                        // The send already succeeded even when sentSaved is false or a pickup link
                        // failed — surface the warning as a notice, never as a failure, and never
                        // offer a retry that would duplicate the message. A non-blank warning (e.g.
                        // "failed to deliver a pickup link to 1 of 3 recipient(s)") is longer than
                        // the plain success message and shown right before finish(), so it needs
                        // LENGTH_LONG to have any chance of being read.
                        val message = warning.ifBlank { getString(R.string.compose_send_success) }
                        val length = if (warning.isBlank()) Toast.LENGTH_SHORT else Toast.LENGTH_LONG
                        Toast.makeText(this, message, length).show()
                        sendSucceeded = true
                        ComposeDraftCache.clear()
                        finish()
                    }
                    is MailOutcome.PickupFallbackNeeded -> {
                        sendMenuItem?.isEnabled = true
                        confirmPickupFallback(outcome.keylessRecipients)
                    }
                    is MailOutcome.ClientSideNeeded -> {
                        sendMenuItem?.isEnabled = true
                        handOffToWebmail()
                    }
                    else -> {
                        sendMenuItem?.isEnabled = true
                        Toast.makeText(this, outcome.userFacingMessage(), Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /**
     * Nothing was delivered when this fires — the relay refuses before any SMTP — so the re-send
     * cannot duplicate the message.
     *
     * The copy is the spec's, verbatim, because it is what makes the opt-in meaningful. Cancel is
     * the negative button and the dialog stays cancelable, so dismissing keeps the composition.
     */
    private fun confirmPickupFallback(keylessRecipients: List<String>) {
        val draft = sentDraft ?: return
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_pickup_dialog_title)
            .setMessage(getString(R.string.compose_pickup_dialog_body, keylessRecipients.joinToString(", ")))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_pickup_dialog_confirm) { _, _ ->
                sendMenuItem?.isEnabled = false
                // The same draft, one flag flipped. Not rebuilt: no re-export of the editor HTML,
                // no re-encoded attachments, no second preflight.
                dispatchSend(draft.copy(allowPickupFallback = true))
            }
            .show()
    }

    /**
     * Saves the composition as a draft and hands the Drafts URL to the **system**, so an installed
     * PWA or the user's browser opens it with the session it already has. Never an in-app WebView:
     * that shares no session and would put an account-password field inside this app.
     *
     * The draft save has to succeed first — opening a browser onto a draft that is not there loses
     * the user's message. The draft is saved without the PGP flags, since [MailDraft]'s sign/encrypt
     * only apply to /api/mail/send, not the plain /api/mail/draft endpoint.
     *
     * Always built from the *current* fields, never from [sentDraft]: unlike the post-409 re-send
     * (where byte-identity with what the relay already evaluated is the whole point), a failed send
     * can leave [sentDraft] holding a stale, pre-edit message. Reusing it here would park that stale
     * draft on the server and silently discard whatever the user typed afterward — see the fix-round
     * report for the traced scenario.
     */
    private fun handOffToWebmail() {
        // Disabled for the whole in-flight window, starting before the async exportHtml/saveDraft
        // round trip even begins: a double-tap in that window would park two drafts and overwrite
        // activeDialog with the second dialog, orphaning the first. Re-enabled on every path that
        // doesn't end in finish() — the two failure toasts below, and the dialog's dismiss
        // listener, which covers Cancel and the no-handler case alike.
        webmailChip.isEnabled = false
        bodyEditor.exportHtml { html ->
            // Same rationale as sendEmail's guard: this callback can fire after onDestroy has torn
            // down ioExecutor.
            if (isFinishing || isDestroyed) return@exportHtml
            val draft = MailDraft(
                to = toInput.commaJoinedRecipients(),
                cc = ccInput.commaJoinedRecipients(),
                bcc = bccInput.commaJoinedRecipients(),
                subject = subjectField.text.toString().trim(),
                body = html,
                mode = "html",
                attachments = attachments.toList(),
            )
            ioExecutor.execute {
                val saved = MailRuntime.graph(this).repository.saveDraft(draft)
                val serverUrl = PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
                val url = serverUrl?.let { webmailDraftsUrl(it) }
                runOnUiThread {
                    // See dispatchSend's identical guard: this callback can also fire after the
                    // Activity has finished (app lock) or been destroyed.
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    when {
                        saved !is MailOutcome.Success -> {
                            webmailChip.isEnabled = true
                            Toast.makeText(
                                this,
                                getString(R.string.compose_handoff_draft_failed, saved.userFacingMessage().orEmpty()),
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                        url == null -> {
                            webmailChip.isEnabled = true
                            Toast.makeText(this, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                        }
                        else -> showHandoffDialog(url)
                    }
                }
            }
        }
    }

    private fun showHandoffDialog(url: String) {
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_handoff_dialog_title)
            .setMessage(R.string.compose_handoff_dialog_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_handoff_dialog_confirm) { _, _ ->
                // Guarded, but not via resolveActivity: minSdk 31 plus no <queries> manifest entry
                // means package-visibility filtering applies to this implicit https intent on every
                // supported device, so resolveActivity can return null even though a browser (which
                // always answers ACTION_VIEW for http/https) is present — a false negative that would
                // stall the only path client-custody accounts have to finish sending. Attempt the
                // launch and catch the (rarer, genuine) no-handler case instead.
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                try {
                    startActivity(intent)
                    finish()
                } catch (e: ActivityNotFoundException) {
                    Toast.makeText(this, R.string.compose_handoff_no_handler, Toast.LENGTH_LONG).show()
                }
            }
            // Re-enables the chip after Cancel and after both positive-button outcomes above —
            // the successful launch doesn't care since finish() is already underway.
            .setOnDismissListener { webmailChip.isEnabled = true }
            .show()
    }

    /**
     * Stashes the composition so the app lock cannot discard it.
     *
     * `onStop` (not `onDestroy`) because [bodyEditor]'s HTML export is asynchronous and needs a
     * live WebView to answer: the Activity is still fully alive here, and the lock's `finish()`
     * does not land until the following `onStart`.
     *
     * Only when the screen is going away for a reason the user did not choose. Pressing Back is a
     * deliberate discard, and resurrecting a message someone threw away is its own bug.
     */
    override fun onStop() {
        super.onStop()
        // onCreate bailed before assigning any view: there is no composition to stash, and
        // touching the lateinit fields below would throw.
        if (redirectedToUnlock) return
        if (isFinishing) {
            ComposeDraftCache.clear()
            return
        }
        if (sendSucceeded) return
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString()
        val currentAttachments = attachments.toList()
        bodyEditor.exportHtml { html ->
            // Guarded like every other exportHtml callback in this file — this one had been missed,
            // and it is the one that writes into a process-scoped static. A security wipe clears
            // ComposeDraftCache as its first step on an IO thread; a callback already queued on the
            // main looper then landed afterwards and put the victim's unsent message straight back
            // into a cache that survives AppRestart.relaunch. ComposeDraftCache also refuses writes
            // while sealed, so this is the second of two gates rather than the only one.
            if (isDestroyed) return@exportHtml
            ComposeDraftCache.save(
                CachedDraft(
                    to = to,
                    cc = cc,
                    bcc = bcc,
                    subject = subject,
                    bodyHtml = html,
                    attachments = currentAttachments,
                ),
            )
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
        // Dismiss rather than leave a shown AlertDialog referencing a destroyed Activity's window.
        activeDialog?.dismiss()
    }

    companion object {
        const val EXTRA_TO = "compose_to"
        const val EXTRA_SUBJECT = "compose_subject"
        const val EXTRA_BODY = "compose_body"

        /** A ready-made HTML quote, for Reply/Forward of an HTML message. Kept separate from
         *  [EXTRA_BODY] because that one is plain text and gets html-escaped on the way in. */
        const val EXTRA_BODY_HTML = "compose_body_html"

        private const val TAG = "ComposeActivity"

        // Mirror of the backend maxMailAttachmentBytes (25 MB total decoded).
        private const val MAX_ATTACHMENT_BYTES = 25L * 1024 * 1024
        private const val MENU_SEND = 1
    }
}

/** Thrown by [readAtMost] so the caller can tell "this file is too big" apart from "this file could
 *  not be read", which a nullable return could not. */
internal class AttachmentTooLargeException : IOException("Attachment exceeds the remaining budget")

/** Copy buffer for [readAtMost]. Large enough that a 25 MB attachment is a few hundred reads, small
 *  enough that the refusal below happens long before the heap notices. */
private const val ATTACHMENT_COPY_BUFFER_BYTES = 64 * 1024

/**
 * Reads [input] fully, or throws [AttachmentTooLargeException] as soon as it has produced more than
 * [limit] bytes — never allocating the whole of an oversized source.
 *
 * Throws rather than returning the prefix, for the same reason
 * [com.urlxl.mail.mail.readBounded] does on the inbound side: a truncated attachment is
 * indistinguishable from a complete one to almost every file format, so returning what it got would
 * mean silently sending a corrupt file.
 *
 * `internal` rather than private so it is reachable from a plain JVM test — the bound is the whole
 * point of this function and the old code had none.
 */
internal fun readAtMost(input: InputStream, limit: Long, expectedSize: Long = -1L): ByteArray {
    // Pre-sized when the provider told us how big the document is, because ByteArrayOutputStream
    // grows by doubling and then `toByteArray()` copies the whole thing again. For a 25 MB
    // attachment that is ~32 MB of internal buffer plus a 25 MB copy, on the way to a ~34 MB base64
    // String — roughly triple the peak of a function whose entire purpose is bounding the heap.
    // Clamped to the budget so a provider that over-reports cannot make us allocate past it.
    val initial = expectedSize.takeIf { it in 0..limit }?.toInt() ?: ATTACHMENT_COPY_BUFFER_BYTES
    val out = ByteArrayOutputStream(initial)
    val buffer = ByteArray(ATTACHMENT_COPY_BUFFER_BYTES)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read == -1) return out.toByteArray()
        total += read
        if (total > limit) throw AttachmentTooLargeException()
        out.write(buffer, 0, read)
    }
}
