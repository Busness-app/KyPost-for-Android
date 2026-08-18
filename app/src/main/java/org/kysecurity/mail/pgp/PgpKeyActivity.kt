package org.kysecurity.mail.pgp

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactsListActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

/**
 * "PGP Key Signing": a single screen that shows the user's own PGP QR code (minted via
 * [PgpQrClient.mintToken], re-minted every time the screen resumes so it's never stale) for
 * someone else to scan, plus a "Scan QR Code" button that scans someone else's code directly —
 * no intermediate navigation screen.
 *
 * On a successful scan, fetches the key via [PgpQrClient.fetchKey] (unauthenticated — the token
 * is the credential), shows the fingerprint for out-of-band confirmation, then either creates a new
 * contact from the included card (if present) or lets the user pick an existing contact (via
 * [ContactsListActivity] in pick mode) to save the key onto.
 *
 * Saving does NOT go through a per-contact REST endpoint — this app never calls those. It follows
 * [org.kysecurity.mail.contacts.ContactEditActivity.save]'s exact pattern instead: `queueUpdate` on the
 * existing [org.kysecurity.mail.contacts.ContactDto] with `pgpKey` set, then `syncNowAsync()`.
 */
class PgpKeyActivity : LockedActivity() {

    private lateinit var qrImage: ImageView
    private lateinit var qrExpiresText: TextView
    private lateinit var qrMyFingerprintText: TextView
    private lateinit var qrStatusText: TextView
    private lateinit var scanStatusText: TextView
    private lateinit var scanNameText: TextView
    private lateinit var scanFingerprintText: TextView
    private lateinit var scanAddressesText: TextView
    private lateinit var confirmButton: Button
    private lateinit var scanButton: Button

    // lazy: pinnedPairingCallFactory(this) needs a valid Context, which isn't available yet at
    // property-initializer time (before attachBaseContext) — deferring to first use (both call
    // sites are well after onCreate) avoids a NullPointerException here. See finding C2 of the
    // 2026-07-22 security-hardening spec's final-review fix round.
    private val client by lazy { PgpQrClient(callFactory = pinnedPairingCallFactory(this)) }
    private val bootstrapClient by lazy { PgpBootstrapClient(callFactory = pinnedPairingCallFactory(this)) }
    private var pendingKey: PgpQrKeyDto? = null

    private val pickContactLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val uid = if (result.resultCode == RESULT_OK) {
            result.data?.getStringExtra(ContactsListActivity.EXTRA_RESULT_UID)
        } else {
            null
        }
        if (!uid.isNullOrBlank()) {
            saveKeyToContact(uid)
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {        setContentView(R.layout.activity_pgp_key)
        setTitle(R.string.pgp_key_signing_title)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.pgpKeyRoot))

        qrImage = findViewById(R.id.pgpQrImage)
        qrExpiresText = findViewById(R.id.pgpQrExpiresText)
        qrMyFingerprintText = findViewById(R.id.pgpQrMyFingerprintText)
        qrStatusText = findViewById(R.id.pgpQrStatusText)
        scanStatusText = findViewById(R.id.pgpScanStatusText)
        scanNameText = findViewById(R.id.pgpScanNameText)
        scanFingerprintText = findViewById(R.id.pgpScanFingerprintText)
        scanAddressesText = findViewById(R.id.pgpScanAddressesText)
        confirmButton = findViewById(R.id.btnConfirmFingerprint)
        scanButton = findViewById(R.id.btnScanPgpQr)

        scanButton.setOnClickListener { scanQr() }
        confirmButton.setOnClickListener { onFingerprintConfirmed() }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, scanButton)
        applyPrimaryButtonTheme(this, confirmButton)
        mintAndRenderOwnQr()
    }

    private fun mintAndRenderOwnQr() {
        qrImage.visibility = View.GONE
        qrExpiresText.text = ""
        qrStatusText.text = getString(R.string.pgp_qr_my_code_loading)

        lifecycleScope.launch {
            val pairing = PushRuntime.graph(this@PgpKeyActivity).repository.pairingForAuthenticatedCall()
            val deviceId = pairing?.deviceId
            val deviceSecret = pairing?.deviceSecret
            if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
                qrStatusText.text = getString(R.string.pgp_qr_my_code_not_paired)
                return@launch
            }

            when (val result = client.mintToken(pairing.serverUrl, deviceId, deviceSecret)) {
                is PgpQrTokenResult.Success -> renderQr(result.token, pairing.serverUrl, deviceId, deviceSecret)
                is PgpQrTokenResult.NoIdentity -> qrStatusText.text = getString(R.string.pgp_qr_my_code_no_identity)
                is PgpQrTokenResult.Unauthorized -> qrStatusText.text = getString(R.string.pgp_qr_my_code_unauthorized)
                is PgpQrTokenResult.ServiceUnavailable -> qrStatusText.text = getString(R.string.pgp_qr_my_code_unavailable)
                is PgpQrTokenResult.Retryable -> qrStatusText.text = result.message
            }
        }
    }

    private fun renderQr(token: PgpQrTokenDto, serverUrl: String, deviceId: String, deviceSecret: String) {
        // Build the URL locally against the paired origin rather than encoding the server-supplied
        // `token.url`. That field was rendered verbatim, so a tampered token response could point
        // the counterparty's unauthenticated fetch at any host — outside the TLS pin — and have
        // them save an attacker's key as ours. The token is the only part we need from the server.
        val ownUrl = ownQrUrl(serverUrl, token.token)
        val bitmap = ownUrl?.let { runCatching { renderQrBitmap(it, QR_SIZE_PX) }.getOrNull() }
        if (bitmap == null) {
            qrStatusText.text = getString(R.string.pgp_qr_my_code_render_failed)
            return
        }
        qrImage.setImageBitmap(bitmap)
        qrImage.visibility = View.VISIBLE
        qrStatusText.text = ""
        qrExpiresText.text = getString(R.string.pgp_qr_my_code_expires, token.expiresAt)
        renderOwnFingerprint(serverUrl, deviceId, deviceSecret)
    }

    /**
     * Shows the user their own fingerprint beside the QR, so that when the other device asks them
     * to "confirm this fingerprint matches", they have something on screen to compare it to.
     */
    private fun renderOwnFingerprint(serverUrl: String, deviceId: String, deviceSecret: String) {
        lifecycleScope.launch {
            val fingerprint = ownFingerprintFromBootstrap(
                bootstrapClient.fetch(serverUrl, deviceId, deviceSecret),
            )
            qrMyFingerprintText.text = if (fingerprint != null) {
                getString(R.string.pgp_qr_my_fingerprint_label, fingerprint)
            } else {
                getString(R.string.pgp_qr_my_fingerprint_unavailable)
            }
            qrMyFingerprintText.visibility = View.VISIBLE
        }
    }

    private fun renderQrBitmap(content: String, sizePx: Int): Bitmap {
        val bitMatrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx)
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.RGB_565)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }

    private fun scanQr() {
        lifecycleScope.launch {
            runCatching {
                GmsBarcodeScanning.getClient(this@PgpKeyActivity).startScan().await().rawValue.orEmpty()
            }.onSuccess { raw ->
                if (raw.isNotBlank()) {
                    handleScanned(raw)
                }
            }.onFailure {
                Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_canceled, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun handleScanned(raw: String) {
        resetConfirmationState()
        val parsed = parsePgpQrKeyUrl(raw)
        if (parsed == null) {
            scanStatusText.text = getString(R.string.pgp_qr_scan_invalid)
            scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
            return
        }

        scanStatusText.text = getString(R.string.pgp_qr_my_code_loading)
        lifecycleScope.launch {
            when (val result = client.fetchKey(parsed.serverUrl, parsed.token)) {
                is PgpQrKeyResult.Success -> showFetchedKey(result.key)
                is PgpQrKeyResult.Forbidden -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_forbidden)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.NotFound -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_not_found)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.ServiceUnavailable -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_unavailable)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.Retryable -> {
                    scanStatusText.text = result.message
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
            }
        }
    }

    private fun showFetchedKey(key: PgpQrKeyDto) {
        // The server's `fingerprint` field is never used for the confirmation prompt below — it's
        // just another claim in the same response as `publicKey`, with no cryptographic tie to it.
        // Computing the fingerprint locally from the key bytes themselves is what makes "confirm
        // this fingerprint matches" an actual verification instead of a rubber stamp.
        val localFingerprint = PgpFingerprint.compute(key.publicKey)
        if (localFingerprint == null) {
            resetConfirmationState()
            scanStatusText.text = getString(R.string.pgp_qr_scan_unparseable_key)
            scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
            return
        }
        pendingKey = key
        scanStatusText.text = getString(R.string.pgp_qr_scan_confirm_prompt)
        scanNameText.text = getString(R.string.pgp_qr_scan_name_label, key.name)
        scanNameText.visibility = View.VISIBLE
        scanFingerprintText.text = getString(R.string.pgp_qr_scan_fingerprint_label, localFingerprint)
        scanFingerprintText.visibility = View.VISIBLE
        // Verifying the fingerprint proves which KEY this is; it says nothing about which
        // addresses the key gets bound to. Those travel beside the key in `contactCard`, are
        // chosen by whoever served the QR, and are what the server's resolver later matches on —
        // so mail to any of them would be encrypted to this key. Show them before accepting.
        val addresses = scannedAddresses(key)
        scanAddressesText.text = if (addresses.isEmpty()) {
            getString(R.string.pgp_qr_scan_addresses_none)
        } else {
            getString(R.string.pgp_qr_scan_addresses_label, addresses.joinToString("\n"))
        }
        scanAddressesText.visibility = View.VISIBLE
        confirmButton.visibility = View.VISIBLE
        scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
    }

    private fun scannedAddresses(key: PgpQrKeyDto): List<String> =
        key.contactCard?.emails.orEmpty().map { it.value }.filter { it.isNotBlank() }

    private fun resetConfirmationState() {
        pendingKey = null
        scanNameText.visibility = View.GONE
        scanFingerprintText.visibility = View.GONE
        scanAddressesText.visibility = View.GONE
        confirmButton.visibility = View.GONE
    }

    private fun onFingerprintConfirmed() {
        val key = pendingKey ?: return
        if (key.contactCard != null) {
            showSaveChoiceDialog(key)
        } else {
            launchContactPicker()
        }
    }

    private fun showSaveChoiceDialog(key: PgpQrKeyDto) {
        val addresses = scannedAddresses(key)
        AlertDialog.Builder(this)
            .setTitle(R.string.pgp_qr_scan_save_choice_title)
            // Restate the binding at the point of commitment: "Create New Contact" writes every
            // address in the card, not just the name shown above it.
            .setMessage(
                if (addresses.isEmpty()) {
                    getString(R.string.pgp_qr_scan_addresses_none)
                } else {
                    getString(R.string.pgp_qr_scan_save_choice_body, addresses.joinToString("\n"))
                },
            )
            .setPositiveButton(R.string.pgp_qr_scan_save_new_button) { _, _ -> createNewContactFromCard(key) }
            .setNegativeButton(R.string.pgp_qr_scan_save_existing_button) { _, _ -> launchContactPicker() }
            .create()
            .showSecurely()
    }

    /**
     * Last gate before a key is bound to an existing contact: shows the addresses that contact
     * currently holds and waits for the user to accept them.
     *
     * The scan confirmation earlier in this flow lists the addresses from the *scanned card*, which
     * on this branch are not the addresses the key ends up bound to — the DTO is built from the Room
     * row. Those two can differ, and a third-party `WRITE_CONTACTS` write is exactly how.
     */
    private suspend fun confirmBinding(name: String, addresses: List<String>): Boolean =
        kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            val body = if (addresses.isEmpty()) {
                getString(R.string.pgp_qr_bind_confirm_body_no_addresses, name)
            } else {
                getString(R.string.pgp_qr_bind_confirm_body, name, addresses.joinToString("\n"))
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.pgp_qr_bind_confirm_title)
                .setMessage(body)
                .setPositiveButton(R.string.pgp_qr_bind_confirm_button) { _, _ ->
                    if (continuation.isActive) continuation.resumeWith(Result.success(true))
                }
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    if (continuation.isActive) continuation.resumeWith(Result.success(false))
                }
                .setOnCancelListener {
                    if (continuation.isActive) continuation.resumeWith(Result.success(false))
                }
                .create()
                .showSecurely()
        }

    private fun launchContactPicker() {
        pickContactLauncher.launch(
            Intent(this, ContactsListActivity::class.java).putExtra(ContactsListActivity.EXTRA_PICK_MODE, true),
        )
    }

    private fun createNewContactFromCard(key: PgpQrKeyDto) {
        val card = key.contactCard ?: return
        val dto = contactDtoFromCard(card, fallbackName = key.name, pgpKey = key.publicKey)
        lifecycleScope.launch {
            val graph = ContactsRuntime.graph(this@PgpKeyActivity)
            graph.repository.queueCreate(dto)
            graph.coordinator.syncNowAsync()

            Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_saved_new, Toast.LENGTH_SHORT).show()
            resetConfirmationState()
            scanStatusText.text = ""
            scanButton.setText(R.string.pgp_qr_scan_scan_button)
        }
    }

    private fun saveKeyToContact(uid: String) {
        val key = pendingKey ?: return
        lifecycleScope.launch {
            val entity = DataRuntime.graph(this@PgpKeyActivity).database.contactDao().getByUid(uid)
            if (entity == null) {
                Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_invalid, Toast.LENGTH_SHORT).show()
                return@launch
            }
            // The addresses the key is about to be bound to are the ones already on THIS contact —
            // not the ones on the scanned card, which is what the confirmation screen showed. Any
            // app holding WRITE_CONTACTS can have rewritten them, so they are restated here, at the
            // point of commitment, before the binding is made.
            val boundAddresses = entity.toDto().emails.map { it.value }.filter { it.isNotBlank() }
            if (!confirmBinding(entity.fn, boundAddresses)) return@launch
            val dto = entity.toDto().copy(pgpKey = key.publicKey)

            val graph = ContactsRuntime.graph(this@PgpKeyActivity)
            // The user just compared this fingerprint out-of-band against the other person's
            // device, so this is a verified rotation, not a suspicious one. Without the flag the
            // mapper raised "Key changed" on the one path where reverification is provably
            // unnecessary, which trains users to dismiss the app's only TOFU alarm.
            // identityChanged = false: this save changes only the key, never the addresses — the
            // DTO is the existing row with pgpKey swapped. It is deliberately not a claim that the
            // addresses are trustworthy; toEntity no longer lets verifiedInPerson clear an
            // identity-rebind alarm, so one raised earlier survives this ceremony.
            graph.repository.queueUpdate(dto, identityChanged = false, verifiedInPerson = true)
            graph.coordinator.syncNowAsync()

            Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_saved, Toast.LENGTH_SHORT).show()
            resetConfirmationState()
            scanStatusText.text = ""
            scanButton.setText(R.string.pgp_qr_scan_scan_button)
        }
    }

    companion object {
        private const val QR_SIZE_PX = 720

        /** The inverse of [parsePgpQrKeyUrl]: builds the URL our own QR encodes, from the paired
         *  server URL plus the minted token. Deliberately does not use the server's `url` field —
         *  see [renderQr]. Returns null if [serverUrl] or [token] can't form a valid URL. */
        internal fun ownQrUrl(serverUrl: String, token: String): String? {
            if (token.isBlank()) return null
            val base = serverUrl.trimEnd('/').toHttpUrlOrNull() ?: return null
            return base.newBuilder()
                .addPathSegments("api/pgp/qr/key")
                .addQueryParameter("t", token)
                .build()
                .toString()
        }

        /** Parses a decoded QR payload into the `(serverUrl, token)` pair [PgpQrClient.fetchKey]
         *  expects. Returns null unless the payload is an `.../api/pgp/qr/key?t=...` URL. */
        internal fun parsePgpQrKeyUrl(raw: String): ParsedPgpQrKeyUrl? {
            val url = raw.trim().toHttpUrlOrNull() ?: return null
            if (url.encodedPath != "/api/pgp/qr/key") return null
            val token = url.queryParameter("t")?.takeIf { it.isNotBlank() } ?: return null
            val serverUrl = HttpUrl.Builder()
                .scheme(url.scheme)
                .host(url.host)
                .port(url.port)
                .build()
                .toString()
                .trimEnd('/')
            return ParsedPgpQrKeyUrl(serverUrl = serverUrl, token = token)
        }

        /** Maps a scanned [PgpQrContactCardDto] to a creatable [ContactDto], for the "Create New
         *  Contact" path in [showSaveChoiceDialog]. [fallbackName] (the scan's top-level `name`)
         *  fills in `fn` when the card itself carries no name — `ContactDto.fn` must be non-blank
         *  per Mobile_Contact_Sync.md, and a card's `fn` is `omitempty` server-side so it can be
         *  legitimately absent. */
        internal fun contactDtoFromCard(card: PgpQrContactCardDto, fallbackName: String, pgpKey: String): ContactDto =
            ContactDto(
                fn = card.fn?.takeIf { it.isNotBlank() } ?: fallbackName.ifBlank { "Unknown" },
                givenName = card.givenName,
                familyName = card.familyName,
                middleName = card.middleName,
                prefix = card.prefix,
                suffix = card.suffix,
                nickname = card.nickname,
                org = card.org,
                title = card.title,
                notes = card.notes,
                birthday = card.birthday,
                emails = card.emails,
                phones = card.phones,
                addresses = card.addresses,
                ims = card.ims,
                websites = card.websites,
                relations = card.relations,
                events = card.events,
                phoneticGivenName = card.phoneticGivenName,
                phoneticFamilyName = card.phoneticFamilyName,
                department = card.department,
                customFields = card.customFields,
                pronouns = card.pronouns,
                pgpKey = pgpKey,
            )
    }
}

internal data class ParsedPgpQrKeyUrl(val serverUrl: String, val token: String)
