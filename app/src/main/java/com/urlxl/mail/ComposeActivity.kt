package com.urlxl.mail

import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.TextUtils
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
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
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
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
    private var sendMenuItem: MenuItem? = null
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val attachments = mutableListOf<OutgoingAttachment>()

    private val pickAttachments = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris -> uris?.forEach(::addAttachment) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)
        applyThemeToActivity(this)

        rootView = findViewById(R.id.composeRoot)
        applyTopInsetWithHeader(this, rootView)

        setTitle(R.string.compose_email)

        subjectField = findViewById(R.id.composeSubjectField)
        bodyEditor = findViewById(R.id.composeBodyEditor)
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

        subjectField.setText(intent.getStringExtra(EXTRA_SUBJECT).orEmpty())
        toInput.setInitialRecipients(intent.getStringExtra(EXTRA_TO).orEmpty())
        val prefillBody = intent.getStringExtra(EXTRA_BODY).orEmpty()
        bodyEditor.setHtml(plainTextToHtml(prefillBody))

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
        applyThemeToActivity(this)
        applyToolbarChipsTheme()
        applySendMenuItemTheme()
        applyEditorThemeCss()
        toInput.applyTheme()
        ccInput.applyTheme()
        bccInput.applyTheme()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
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
        listOf(boldChip, italicChip, underlineChip, linkChip, attachButton).forEach {
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

    /** Reads the picked document off the UI thread's ContentResolver, base64-encodes it, enforces
     *  the 25 MB total cap (matching the backend), and renders a removable chip. */
    private fun addAttachment(uri: Uri) {
        val resolver = contentResolver
        var name = "attachment"
        var size = 0L
        runCatching {
            resolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIdx >= 0 && !cursor.isNull(nameIdx)) name = cursor.getString(nameIdx)
                    val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) size = cursor.getLong(sizeIdx)
                }
            }
        }
        val bytes = runCatching { resolver.openInputStream(uri)?.use { it.readBytes() } }.getOrNull()
        if (bytes == null) {
            Toast.makeText(this, "Couldn't read $name", Toast.LENGTH_SHORT).show()
            return
        }
        val currentTotal = attachments.sumOf { it.size.toLong() }
        if (currentTotal + bytes.size > MAX_ATTACHMENT_BYTES) {
            Toast.makeText(this, getString(R.string.compose_attachments_too_large), Toast.LENGTH_LONG).show()
            return
        }
        val mimeType = resolver.getType(uri) ?: "application/octet-stream"
        attachments.add(
            OutgoingAttachment(
                name = name,
                mimeType = mimeType,
                dataBase64 = Base64.encodeToString(bytes, Base64.NO_WRAP),
                size = bytes.size,
            ),
        )
        renderAttachmentChips()
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
            Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show()
            return
        }

        sendMenuItem?.isEnabled = false

        bodyEditor.exportHtml { html ->
            ioExecutor.execute {
                val outcome = MailRuntime.graph(this).repository.send(
                    MailDraft(to = to, cc = cc, bcc = bcc, subject = subject, body = html, mode = "html", attachments = attachments.toList()),
                )
                runOnUiThread {
                    when (outcome) {
                        is MailOutcome.Success -> {
                            val warning = outcome.value.warning
                            // The send already succeeded even when sentSaved is false — surface the
                            // warning as a non-blocking notice, not a failure.
                            val message = warning.ifBlank { "Email sent successfully" }
                            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
                            finish()
                        }
                        else -> {
                            sendMenuItem?.isEnabled = true
                            Toast.makeText(this, outcome.userFacingMessage(), Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        ioExecutor.shutdownNow()
    }

    companion object {
        const val EXTRA_TO = "compose_to"
        const val EXTRA_SUBJECT = "compose_subject"
        const val EXTRA_BODY = "compose_body"

        // Mirror of the backend maxMailAttachmentBytes (25 MB total decoded).
        private const val MAX_ATTACHMENT_BYTES = 25L * 1024 * 1024
        private const val MENU_SEND = 1
    }
}
