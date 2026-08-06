package com.urlxl.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.urlxl.mail.R
import com.urlxl.mail.addViewSpaced
import com.urlxl.mail.applyDangerButtonTheme
import com.urlxl.mail.applyPrimaryButtonTheme
import com.urlxl.mail.applySectionEyebrowLabel
import com.urlxl.mail.applyThemeToActivity
import com.urlxl.mail.applyTopInsetWithHeader
import com.urlxl.mail.applyWarningCalloutTheme
import com.urlxl.mail.contacts.device.DeviceContactSyncScheduler
import com.urlxl.mail.contacts.device.DeviceContactsRuntime
import com.urlxl.mail.dpToPx
import com.urlxl.mail.pgp.AndroidIdentitySource
import com.urlxl.mail.pgp.DeviceEnrollmentActivity
import com.urlxl.mail.pgp.EnrollmentRow
import com.urlxl.mail.pgp.EnrollmentStatus
import com.urlxl.mail.pgp.EnrollmentTeardown
import com.urlxl.mail.pgp.EnrollmentVault
import com.urlxl.mail.pgp.IdentityCheck
import com.urlxl.mail.pgp.enrollmentRowFor
import com.urlxl.mail.pgp.hasSecureLockScreen
import com.urlxl.mail.pgp.openWebmail
import com.urlxl.mail.pgp.probeEnrollment
import com.urlxl.mail.pgp.webmailHomeUrl
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The context every security-critical background step in this screen runs on.
 *
 * `withContext(NonCancellable)` alone was the bug: [NonCancellable] is a [kotlinx.coroutines.Job],
 * and `withContext` replaces only the elements it is given — the `ContinuationInterceptor` is
 * inherited. `lifecycleScope` is `Dispatchers.Main.immediate`, so every block below was running
 * 150,000 rounds of PBKDF2, a Keystore round trip and a synchronous `commit()` on the UI thread,
 * under comments asserting the opposite.
 */
private val SecurityWork = Dispatchers.Default + NonCancellable

/**
 * Destroys this device's enrollment and enqueues the correction, for the Hostile Location
 * Protection toggle.
 *
 * Top-level rather than a private method so the instrumented test drives the same code the toggle
 * does. A test that re-implemented the sequence would stay green after the toggle stopped calling
 * it — which is the failure mode this whole path exists to prevent.
 *
 * Unlike [SecurityWipe], this leaves the pairing alone: protection keeps push and sync working, and
 * only the ability to open the envelope goes away.
 *
 * A teardown that could not fully complete is logged rather than surfaced. The enqueued report is
 * the honest half — it probes live state, so if the envelope did survive, the server is told this
 * device is still enrolled rather than being told a comforting lie.
 */
internal fun tearDownEnrollmentForHostileLocation(context: android.content.Context) {
    val leftBehind = com.urlxl.mail.pgp.EnrollmentTeardown.destroy(context)
    if (leftBehind.isNotEmpty()) {
        android.util.Log.e(
            "SecuritySettings",
            "Enrollment teardown left $leftBehind behind while enabling protection",
        )
    }
    com.urlxl.mail.pgp.EnrollmentStateWorker.enqueue(context)
}

/**
 * "Security" settings: Require Unlock to Open, Hostile Location Protection, and the credential
 * PIN-gate. Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented.
 */
class SecuritySettingsActivity : LockedActivity() {

    private lateinit var appLockStore: AppLockStore
    private lateinit var lockSwitch: SwitchCompat
    private lateinit var changePinButton: Button
    private lateinit var lockGraceButton: Button
    private lateinit var biometricSwitch: SwitchCompat
    private lateinit var hostileLocationSwitch: SwitchCompat
    private lateinit var hostileLocationIntro: TextView
    private lateinit var credentialGateSwitch: SwitchCompat
    private lateinit var encryptionSectionLabel: TextView
    private lateinit var encryptionRowText: TextView
    private lateinit var encryptionActionButton: Button
    private var suppressLockToggleListener = false
    private var suppressCredentialGateListener = false
    private var suppressHostileLocationListener = false

    /**
     * Every persisted value this screen renders, read in one pass.
     *
     * Read once, off the main thread, because seven of these come out of a Keystore-backed
     * `EncryptedSharedPreferences` — the store whose own KDoc says "[AppLockManager] keeps every
     * caller off the main thread so the durability can be afforded", while this screen read it
     * seven times from `onCreate` and wrote it with `commit()` from a click listener.
     */
    private data class SettingsSnapshot(
        val lockEnabled: Boolean,
        val biometricEnabled: Boolean,
        val credentialGateEnabled: Boolean,
        val hostileLocationEnabled: Boolean,
        val graceMillis: Long,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return
        appLockStore = SecurityRuntime.graph(this).appLockStore
        setTitle(R.string.security_settings_title)

        lifecycleScope.launch {
            val graph = SecurityRuntime.graph(this@SecuritySettingsActivity)
            val snapshot = withContext(SecurityWork) {
                SettingsSnapshot(
                    lockEnabled = appLockStore.isLockEnabled(),
                    biometricEnabled = appLockStore.isBiometricEnabled(),
                    credentialGateEnabled = appLockStore.isCredentialPinGateEnabled(),
                    hostileLocationEnabled = graph.hostileLocationSettings.isEnabled(),
                    graceMillis = graph.appLockSettings.graceMillis(),
                )
            }
            if (isFinishing || isDestroyed) return@launch
            buildViews(snapshot)
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        // ::isInitialized guards the window between onCreate's launch starting and buildViews
        // running — onResume can fire first, and these are lateinit.
        if (::encryptionRowText.isInitialized) refreshEncryptionRow()
    }

    private fun buildViews(snapshot: SettingsSnapshot) {
        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        lockSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_require_unlock_title)
            isChecked = snapshot.lockEnabled
        }
        container.addViewSpaced(lockSwitch, bottomDp = 4)
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_require_unlock_intro)
                textSize = 13f
            },
            bottomDp = 20,
        )

        changePinButton = Button(this).apply {
            text = getString(R.string.security_change_pin_button)
            visibility = if (snapshot.lockEnabled) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        container.addViewSpaced(changePinButton, bottomDp = 16)

        biometricSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = snapshot.biometricEnabled
            isEnabled = snapshot.lockEnabled
        }
        container.addViewSpaced(biometricSwitch, bottomDp = 20)

        // How long backgrounding is tolerated before the lock re-engages. This existed only as a
        // hardcoded "immediately", which meant the attachment picker, the QR scanner and the
        // webmail handoff each destroyed the screen that launched them — see KyPostApp.onStop.
        val lockGraceSettings = SecurityRuntime.graph(this).appLockSettings
        lockGraceButton = Button(this).apply {
            text = lockGraceButtonLabel(snapshot.graceMillis)
            isEnabled = snapshot.lockEnabled
            setOnClickListener { promptLockGrace(lockGraceSettings) }
        }
        container.addViewSpaced(lockGraceButton, bottomDp = 4)
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_lock_grace_intro)
                textSize = 13f
            },
            bottomDp = 20,
        )

        val hostileLocationSettings = SecurityRuntime.graph(this).hostileLocationSettings
        hostileLocationSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_hostile_location_title)
            isChecked = snapshot.hostileLocationEnabled
            isEnabled = snapshot.lockEnabled
        }
        container.addViewSpaced(hostileLocationSwitch, bottomDp = 4)
        hostileLocationIntro = TextView(this).apply {
            text = if (snapshot.lockEnabled) {
                getString(R.string.security_hostile_location_intro)
            } else {
                getString(R.string.security_hostile_location_requires_lock)
            }
            textSize = 13f
        }
        container.addViewSpaced(hostileLocationIntro, bottomDp = 20)
        hostileLocationSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressHostileLocationListener) return@setOnCheckedChangeListener
            // Confirmed, because this is the most destructive control on the screen and was the
            // only one without a prompt: it deletes every cached message, purges the contacts this
            // app wrote into the OS provider, removes the sync account and relaunches — on one
            // stray tap. Unpairing and pairing, both strictly less destructive, have confirmed for
            // some time.
            AlertDialog.Builder(this)
                .setTitle(
                    if (checked) R.string.security_hostile_location_confirm_enable_title
                    else R.string.security_hostile_location_confirm_disable_title,
                )
                .setMessage(
                    if (checked) R.string.security_hostile_location_confirm_enable_body
                    else R.string.security_hostile_location_confirm_disable_body,
                )
                .setPositiveButton(R.string.security_hostile_location_confirm_positive) { _, _ ->
                    applyHostileLocationProtection(hostileLocationSettings, checked)
                }
                .setNegativeButton(R.string.cancel) { _, _ -> revertHostileLocationSwitch(!checked) }
                .setOnCancelListener { revertHostileLocationSwitch(!checked) }
                .show()
        }

        credentialGateSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_credential_gate_title)
            isChecked = snapshot.credentialGateEnabled
            isEnabled = snapshot.lockEnabled
        }
        container.addViewSpaced(credentialGateSwitch, bottomDp = 4)
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_intro)
                textSize = 13f
            },
            bottomDp = 8,
        )
        // Always visible regardless of credentialGateSwitch's state: the push-relay exposure this
        // describes exists on every push delivery, on or off — this toggle only ever controlled
        // whether content is withheld while locked, not whether the relay sees it.
        container.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_leak_warning)
                textSize = 13f
                setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10))
                applyWarningCalloutTheme(this@SecuritySettingsActivity, this)
            },
            bottomDp = 16,
        )
        credentialGateSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressCredentialGateListener) return@setOnCheckedChangeListener
            if (checked) confirmEnableCredentialGate() else confirmDisableCredentialGate()
        }

        lockSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressLockToggleListener) return@setOnCheckedChangeListener
            onLockToggle(checked)
        }
        // commit()-backed write into the Keystore-backed store — an fsync plus AES-GCM, which is
        // not something a click listener may do on the main thread. Every other write on this
        // screen already goes through SecurityWork; this one had been missed.
        biometricSwitch.setOnCheckedChangeListener { _, checked ->
            lifecycleScope.launch { withContext(SecurityWork) { appLockStore.setBiometricEnabled(checked) } }
        }

        // Encrypted mail. Built hidden and filled in asynchronously: deciding the row needs a
        // Keystore probe and (usually) one authenticated request, neither of which may run on the
        // main thread or block the rest of this screen from appearing.
        encryptionSectionLabel = TextView(this).apply {
            text = getString(R.string.security_encryption_section)
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionSectionLabel, topDp = 8, bottomDp = 8)
        encryptionRowText = TextView(this).apply {
            textSize = 13f
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionRowText, bottomDp = 8)
        encryptionActionButton = Button(this).apply { visibility = View.GONE }
        container.addViewSpaced(encryptionActionButton, bottomDp = 16)

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)
        refreshEncryptionRow()
    }

    /**
     * Recomputes the encrypted-mail row.
     *
     * The identity request is skipped whenever a local fact already decides the row. That is not
     * only an optimisation: under Hostile Location Protection the user has just declared this
     * network hostile, and this screen must not answer that by making a request over it.
     */
    private fun refreshEncryptionRow() {
        lifecycleScope.launch {
            val activity = this@SecuritySettingsActivity
            val local = withContext(SecurityWork) {
                val pairing = PushRuntime.graph(activity).repository.pairingForAuthenticatedCall()
                Triple(
                    pairing != null && !pairing.deviceId.isNullOrBlank(),
                    SecurityRuntime.graph(activity).hostileLocationSettings.isEnabled(),
                    hasSecureLockScreen(activity),
                )
            }
            val (paired, hostileLocation, lockScreen) = local
            val status = withContext(SecurityWork) {
                probeEnrollment(EnrollmentVault(activity))
            }
            // SecurityWork, like the reads above: check() calls pairingForAuthenticatedCall()
            // before its own withContext(Dispatchers.IO), and that pairing read is several
            // EncryptedSharedPreferences decrypts plus a CredentialCipher.unwrap AES operation —
            // the same class of Keystore work SecurityWork's own KDoc exists to keep off the main
            // thread, wrapping only the network fetch inside check() would have missed it.
            //
            // `status` is part of the guard, not just the three booleans: enrollmentRowFor decides
            // on KEY_INVALIDATED and ENROLLED *before* it ever looks at `identity`, so on an
            // already-enrolled device the request below was made on every visit to this screen and
            // its answer thrown away.
            val statusDecides = status == EnrollmentStatus.KEY_INVALIDATED ||
                status == EnrollmentStatus.ENROLLED
            val identity = if (paired && !hostileLocation && lockScreen && !statusDecides) {
                withContext(SecurityWork) { AndroidIdentitySource(activity).check() }
            } else {
                IdentityCheck.CouldNotCheck
            }
            if (isFinishing || isDestroyed) return@launch
            renderEncryptionRow(
                enrollmentRowFor(
                    paired = paired,
                    hostileLocation = hostileLocation,
                    hasSecureLockScreen = lockScreen,
                    status = status,
                    identity = identity,
                ),
            )
        }
    }

    private fun renderEncryptionRow(row: EnrollmentRow) {
        if (row is EnrollmentRow.Hidden) {
            encryptionSectionLabel.visibility = View.GONE
            encryptionRowText.visibility = View.GONE
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionSectionLabel.visibility = View.VISIBLE
        applySectionEyebrowLabel(this, encryptionSectionLabel)
        encryptionRowText.visibility = View.VISIBLE
        encryptionRowText.setText(encryptionRowCopy(row))

        val action: Pair<Int, () -> Unit>? = when (row) {
            EnrollmentRow.ServerHeldKey,
            EnrollmentRow.NoIdentity,
            -> R.string.security_encryption_open_webmail to { openAccountWebmail() }

            EnrollmentRow.NotEnrolled ->
                R.string.security_encryption_set_up to { launchEnrollmentCeremony() }

            EnrollmentRow.KeyInvalidated ->
                R.string.security_encryption_set_up_again to { launchEnrollmentCeremony() }

            EnrollmentRow.Enrolled ->
                R.string.security_encryption_remove to { confirmRemoveEnrollment() }

            // Nothing the user can do from here fixes any of these.
            EnrollmentRow.HostileLocation,
            EnrollmentRow.NoSecureLockScreen,
            EnrollmentRow.CouldNotCheck,
            EnrollmentRow.Hidden,
            -> null
        }

        if (action == null) {
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionActionButton.visibility = View.VISIBLE
        encryptionActionButton.setText(action.first)
        encryptionActionButton.setOnClickListener { action.second() }
        if (row is EnrollmentRow.Enrolled) {
            applyDangerButtonTheme(this, encryptionActionButton)
        } else {
            applyPrimaryButtonTheme(this, encryptionActionButton)
        }
    }

    private fun encryptionRowCopy(row: EnrollmentRow): Int = when (row) {
        EnrollmentRow.Hidden -> R.string.empty_string
        EnrollmentRow.HostileLocation -> R.string.security_encryption_hostile_location
        EnrollmentRow.NoSecureLockScreen -> R.string.security_encryption_no_lock_screen
        EnrollmentRow.KeyInvalidated -> R.string.security_encryption_invalidated
        EnrollmentRow.Enrolled -> R.string.security_encryption_enrolled
        EnrollmentRow.ServerHeldKey -> R.string.security_encryption_server_held
        EnrollmentRow.NoIdentity -> R.string.security_encryption_no_identity
        EnrollmentRow.CouldNotCheck -> R.string.security_encryption_could_not_check
        EnrollmentRow.NotEnrolled -> R.string.security_encryption_not_enrolled
    }

    private fun launchEnrollmentCeremony() {
        startActivity(Intent(this, DeviceEnrollmentActivity::class.java))
    }

    /** Built from the pairing's own `serverUrl`, never from anything a response supplied —
     *  `openWebmail` refuses a non-first-party URL rather than degrading to a browser launch. */
    private fun openAccountWebmail() {
        lifecycleScope.launch {
            val serverUrl = withContext(SecurityWork) {
                PushRuntime.graph(this@SecuritySettingsActivity)
                    .repository.pairingForAuthenticatedCall()?.serverUrl
            }
            val url = serverUrl?.let { webmailHomeUrl(it) }
            val opened = url != null &&
                openWebmail(this@SecuritySettingsActivity, serverUrl, url)
            if (!opened) {
                Toast.makeText(
                    this@SecuritySettingsActivity,
                    R.string.security_encryption_webmail_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    /**
     * Confirmed, because it is destructive and not obviously reversible from the user's side: the
     * envelope goes, and getting it back means another two-device ceremony.
     */
    private fun confirmRemoveEnrollment() {
        AlertDialog.Builder(this)
            .setTitle(R.string.security_encryption_remove_title)
            .setMessage(R.string.security_encryption_remove_body)
            .setPositiveButton(R.string.security_encryption_remove_confirm) { _, _ ->
                lifecycleScope.launch {
                    // SecurityWork, like every other destructive step on this screen: this is a
                    // Keystore deletion plus a commit()-backed prefs clear.
                    val leftBehind = withContext(SecurityWork) {
                        EnrollmentTeardown.destroyAndReport(
                            this@SecuritySettingsActivity,
                        )
                    }
                    if (leftBehind.isNotEmpty()) {
                        android.util.Log.e(
                            "SecuritySettings",
                            "Enrollment removal left $leftBehind behind",
                        )
                    }
                    if (isFinishing || isDestroyed) return@launch
                    // The enqueued report probes live state, so a half-failed teardown is reported
                    // honestly rather than as a removal that did not happen.
                    Toast.makeText(
                        this@SecuritySettingsActivity,
                        R.string.security_encryption_removed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    refreshEncryptionRow()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Same re-entrancy hazard as [revertLockSwitch], guarded the same way. */
    private fun revertHostileLocationSwitch(checked: Boolean) {
        suppressHostileLocationListener = true
        hostileLocationSwitch.isChecked = checked
        suppressHostileLocationListener = false
    }

    private fun applyHostileLocationProtection(settings: HostileLocationSettings, enable: Boolean) {
        lifecycleScope.launch {
            // The relaunch is part of the non-cancellable unit, not a statement after it. It used
            // to sit outside, which made it an ordinary cancellable continuation: a Back press or a
            // rotation during the multi-second teardown killed lifecycleScope, the flag still
            // committed under NonCancellable, and the process reset was silently skipped — leaving
            // the previous session's decrypted attachments and draft resident under a switch
            // reading ON. See [runSecurityChangeThenReset].
            runSecurityChangeThenReset(
                workContext = SecurityWork,
                reset = {
                    withContext(Dispatchers.Main) { AppRestart.relaunch(this@SecuritySettingsActivity) }
                },
                change = {
                if (enable) disableAndPurgeDeviceContactSync()
                // Both directions need a fresh on-disk kypost_mail.db afterward: enabling must
                // not leave the pre-toggle disk cache behind, and this is a harmless no-op on
                // the disable path.
                SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
                if (enable) {
                    // "Nothing from before the toggle survives" has to include the plaintext
                    // metadata stores, not just the database — push_state alone held sender and
                    // subject for the last 30 messages.
                    SecurityWipe.deletePlaintextMetadataStores(this@SecuritySettingsActivity)
                    // ...and the attachments the user tapped while protection was off, which are
                    // written to shared Downloads with no prompt and sit OUTSIDE the sandbox. The
                    // confirmation the user just read says "No mail, contacts, or attachments are
                    // cached on this device... Turning this on immediately wipes what's cached now".
                    // The full wipe learned to clear these; this sibling path had not.
                    runCatching { DownloadedAttachmentLedger.deleteAll(this@SecuritySettingsActivity) }
                        .onFailure {
                            android.util.Log.e(
                                "SecuritySettings",
                                "Could not erase downloaded attachments while enabling protection",
                                it,
                            )
                        }
                    // Before the flag flips, so every interruption point is safe: a process death
                    // after this leaves the flag off with the envelope already gone — honestly
                    // un-enrolled — rather than protection on with a readable envelope, which is
                    // the state this mode exists to prevent.
                    tearDownEnrollmentForHostileLocation(this@SecuritySettingsActivity)
                }
                settings.setEnabled(enable)
                },
            )
        }
    }

    private fun lockGraceButtonLabel(millis: Long): String =
        getString(R.string.security_lock_grace_button, lockGraceLabel(millis))

    private fun lockGraceLabel(millis: Long): String = when (millis) {
        0L -> getString(R.string.security_lock_grace_immediately)
        else -> resources.getQuantityString(
            R.plurals.security_lock_grace_seconds,
            (millis / 1_000L).toInt(),
            (millis / 1_000L).toInt(),
        )
    }

    private fun promptLockGrace(settings: AppLockSettings) {
        val options = AppLockSettings.OPTIONS_MILLIS
        val labels = options.map { lockGraceLabel(it) }.toTypedArray()
        val current = options.indexOfFirst { it == settings.graceMillis() }.takeIf { it >= 0 } ?: 0
        AlertDialog.Builder(this)
            .setTitle(R.string.security_lock_grace_dialog_title)
            .setSingleChoiceItems(labels, current) { dialog, which ->
                settings.setGraceMillis(options[which])
                lockGraceButton.text = lockGraceButtonLabel(options[which])
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    /**
     * Turning Hostile Location Protection on has to undo any contact sync that already happened:
     * those rows live in the OS contacts provider, which protection's in-memory database does not
     * cover, so leaving them would keep publishing exactly what the feature promises to withhold.
     */
    private suspend fun disableAndPurgeDeviceContactSync() {
        val graph = DeviceContactsRuntime.graph(this)
        runCatching {
            graph.settings.setEnabled(false)
            DeviceContactSyncScheduler.cancelPeriodic(this)
            graph.repository.deleteAllSyncedDeviceContacts()
            graph.accountManager.removeAccount()
        }.onFailure { android.util.Log.e("SecuritySettings", "Failed to purge device contacts", it) }
    }

    private fun onLockToggle(checked: Boolean) {
        if (checked) {
            promptSetPin()
        } else {
            promptDisableLock()
        }
    }

    /**
     * Reverts [lockSwitch] to [checked] without re-firing its listener. Used whenever we undo the
     * user's toggle because the set-PIN or disable-lock flow was cancelled or failed.
     */
    private fun revertLockSwitch(checked: Boolean) {
        suppressLockToggleListener = true
        lockSwitch.isChecked = checked
        suppressLockToggleListener = false
    }

    /** Same re-entrancy hazard as [revertLockSwitch], guarded the same way. */
    private fun revertCredentialGateSwitch(checked: Boolean) {
        suppressCredentialGateListener = true
        credentialGateSwitch.isChecked = checked
        suppressCredentialGateListener = false
    }

    /**
     * Shows a two-field "enter PIN, then confirm it" dialog — a typo in the single-entry flow this
     * replaced would permanently lock the PIN in with no recovery except 10 deliberate wrong
     * attempts (which wipes) or a reinstall, so every *new* PIN goes through enter+confirm.
     *
     * A rejected PIN now always says why and reopens. It used to fall through to [onCancelled] for
     * anything that wasn't exactly 6 digits, which silently flipped the toggle back with no
     * message at all and read as the app being broken.
     */
    private fun promptEnterAndConfirmPin(onConfirmed: (String) -> Unit, onCancelled: () -> Unit) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        val confirmField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.security_confirm_pin_hint)
        }
        val fieldsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(pinField)
            addView(confirmField)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.security_set_pin_title)
            .setView(fieldsContainer)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ ->
                val pin = pinField.text.toString()
                val confirm = confirmField.text.toString()
                val policyError = pinPolicyMessage(PinPolicy.validate(pin))
                when {
                    policyError != null -> {
                        Toast.makeText(this, policyError, Toast.LENGTH_LONG).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    pin != confirm -> {
                        Toast.makeText(this, R.string.security_pin_mismatch, Toast.LENGTH_SHORT).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    else -> onConfirmed(pin)
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setCancelable(false)
            // FLAG_SECURE lives on the Activity window and a Dialog has its own, so this PIN was
            // screenshot- and screen-recordable while the identical field on UnlockActivity was
            // not. See [showSecurely].
            .create()
            .showSecurely()
    }

    private fun pinPolicyMessage(result: PinPolicy.Result): String? = when (result) {
        PinPolicy.Result.Valid -> null
        PinPolicy.Result.TooShort -> getString(R.string.security_pin_too_short, PinPolicy.MIN_LENGTH)
        PinPolicy.Result.TooLong -> getString(R.string.security_pin_too_long, PinPolicy.MAX_LENGTH)
        PinPolicy.Result.NotNumeric -> getString(R.string.security_pin_not_numeric)
        PinPolicy.Result.TooCommon -> getString(R.string.security_pin_too_common)
    }

    private fun promptSetPin() {
        promptEnterAndConfirmPin(
            onConfirmed = { pin ->
                lifecycleScope.launch {
                    // setPin runs PBKDF2 and two commit()-backed Keystore writes — see [SecurityWork]
                    // for why NonCancellable on its own did not move any of it off the main thread.
                    withContext(SecurityWork) {
                        appLockStore.setPin(pin)
                        appLockStore.setLockEnabled(true)
                    }
                    changePinButton.visibility = View.VISIBLE
                    lockGraceButton.isEnabled = true
                    biometricSwitch.isEnabled = true
                    hostileLocationSwitch.isEnabled = true
                    hostileLocationIntro.text = getString(R.string.security_hostile_location_intro)
                    credentialGateSwitch.isEnabled = true
                }
            },
            onCancelled = { revertLockSwitch(false) },
        )
    }

    /** Requires the CURRENT PIN first (same verification as [promptDisableLock]) before minting a
     *  new one via the same enter+confirm flow [promptSetPin] uses. */
    private fun promptChangePin() {
        promptForPin(R.string.security_change_pin_title) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                // resolvePinAttempt, not `is Success`: this check runs the same wipe threshold as
                // the unlock screen, and collapsing Wiped into "wrong PIN" left the user in a
                // settings screen for an app whose data had just been destroyed. See [PinGate].
                val ok = resolvePinAttempt(appLockManager.verifyPinThrottled(entered))
                if (ok) {
                    promptEnterAndConfirmPin(
                        onConfirmed = { newPin ->
                            lifecycleScope.launch {
                                if (!changePin(oldPin = entered, newPin = newPin)) {
                                    Toast.makeText(
                                        this@SecuritySettingsActivity,
                                        R.string.security_change_pin_secret_unreadable,
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        },
                        onCancelled = {},
                    )
                } else {
                    Toast.makeText(this@SecuritySettingsActivity, R.string.security_pin_incorrect, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Rotates the PIN, re-wrapping `deviceSecret` in the same step when the credential gate is on.
     *
     * The wrapping key is derived from the PIN and a salt that deliberately does not rotate, so
     * writing the new PIN hash alone silently orphaned the secret: the new PIN derives a different
     * key, the GCM tag then fails, and every authenticated call 401s while the UI still says
     * "Paired". `needsCredentialRewrap()` cannot see it either — the ciphertext is present and at
     * the current version, it just no longer opens — so nothing repaired it, and the obvious
     * recovery (turning the gate off) destroyed the ciphertext outright. Unwrap with the old key
     * before overwriting the hash, then re-wrap with the new one, all under NonCancellable.
     */
    private suspend fun changePin(oldPin: String, newPin: String): Boolean = withContext(SecurityWork) {
        val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
        val securePairingStore = PushRuntime.graph(this@SecuritySettingsActivity).securePairingStore
        val gateEnabled = appLockStore.isCredentialPinGateEnabled()
        val salt = appLockStore.credentialSalt()

        val pairing = if (gateEnabled && salt != null) {
            val oldKeys = CredentialCipher.deriveKeys(oldPin, salt)
            securePairingStore.pairingSnapshot(oldKeys)
        } else {
            null
        }

        // ABORT BEFORE THE DESTRUCTIVE WRITE, not after it.
        //
        // The re-wrap below is skipped whenever `deviceSecret` comes back null — and the fix that
        // introduced this function only ever considered the case where there is no secret to
        // re-wrap. There is a second way to get null: the unwrap *failed* (the Keystore wrapping
        // key rotated, the ciphertext was damaged). Overwriting the PIN hash in that state leaves
        // ciphertext that nothing can ever open, `needsCredentialRewrap()` reports false because it
        // is present and current-versioned, so no repair path ever runs — and every authenticated
        // call 401s behind a UI still reading "Paired". Refuse instead, and leave the old PIN
        // working so the user still has a device they can use.
        val hasPairingToProtect = gateEnabled && salt != null && securePairingStore.needsCredentialRewrap().not() &&
            securePairingStore.pairingSnapshot(null) != null
        if (hasPairingToProtect && pairing?.deviceSecret.isNullOrBlank()) {
            android.util.Log.e(
                "SecuritySettings",
                "Refusing to change the PIN: the wrapped device secret could not be read with the old PIN",
            )
            return@withContext false
        }

        appLockStore.setPin(newPin)

        if (gateEnabled && salt != null) {
            // Re-derive under the new PIN and cache, so savePairing's gate-on branch can wrap.
            appLockManager.deriveAndCacheCredentialKeys(newPin)
            if (pairing?.deviceSecret != null) {
                PushRuntime.graph(this@SecuritySettingsActivity).repository.savePairing(pairing)
            }
        }
        true
    }

    private fun promptDisableLock() {
        promptForPin(
            titleRes = R.string.security_confirm_disable_title,
            onCancelled = { revertLockSwitch(true) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                val ok = resolvePinAttempt(appLockManager.verifyPinThrottled(entered))
                if (ok) disableLock() else revertLockSwitch(true)
            }
        }
    }

    /**
     * Runs once the disabling user has re-verified their current PIN. A full [SecurityWipe] is
     * only necessary when the credential gate was on: that's what leaves a PIN-wrapped
     * `deviceSecret` behind with no way to ever unwrap it once the PIN is gone. When the gate
     * wasn't on, clearing the app-lock state is enough — destroying a working pairing on a routine
     * settings change buys no security that toggle 1 alone ever promised.
     */
    private suspend fun disableLock() {
        val settings = SecurityRuntime.graph(this).hostileLocationSettings
        // Named, not a Pair: these two flags select different teardown paths below, and `.first` /
        // `.second` at the branch points would say nothing about which is which.
        data class PriorState(val hostileLocation: Boolean, val credentialGate: Boolean)

        // Both reads and the write are commit()-backed, and one of them opens the Keystore-backed
        // store, so they belong on [SecurityWork] like every other write in this screen.
        val prior = withContext(SecurityWork) {
            PriorState(
                hostileLocation = settings.isEnabled(),
                credentialGate = appLockStore.isCredentialPinGateEnabled(),
            ).also { settings.setEnabled(false) }
        }

        // Both branches below pair a destructive step with the relaunch that completes it, and both
        // had the same split as the hostile-location toggle: the destruction runs NonCancellable
        // inside SecurityWipe, the relaunch after it does not. See [runSecurityChangeThenReset].
        if (prior.credentialGate) {
            runSecurityChangeThenReset(
                workContext = SecurityWork,
                change = { SecurityWipe.wipeAndResetApp(this@SecuritySettingsActivity) },
                reset = {
                    withContext(Dispatchers.Main) { AppRestart.relaunch(this@SecuritySettingsActivity) }
                },
            )
            return
        }

        withContext(SecurityWork) { appLockStore.reset() }

        if (prior.hostileLocation) {
            runSecurityChangeThenReset(
                workContext = SecurityWork,
                change = { SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity) },
                reset = {
                    withContext(Dispatchers.Main) { AppRestart.relaunch(this@SecuritySettingsActivity) }
                },
            )
            return
        }

        changePinButton.visibility = View.GONE
        lockGraceButton.isEnabled = false
        biometricSwitch.isChecked = false
        biometricSwitch.isEnabled = false
        hostileLocationSwitch.isEnabled = false
        hostileLocationIntro.text = getString(R.string.security_hostile_location_requires_lock)
        credentialGateSwitch.isEnabled = false
    }

    private fun confirmEnableCredentialGate() {
        AlertDialog.Builder(this)
            .setTitle(R.string.security_credential_gate_warning_title)
            .setMessage(R.string.security_credential_gate_warning_body)
            .setPositiveButton(R.string.security_credential_gate_warning_confirm) { _, _ -> promptCredentialGatePin(enabling = true) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> revertCredentialGateSwitch(false) }
            .setCancelable(false)
            .show()
    }

    private fun confirmDisableCredentialGate() {
        promptCredentialGatePin(enabling = false)
    }

    /**
     * Both directions need the PIN re-entered here (not just "the app happens to be unlocked right
     * now") to guarantee a fresh PIN-derived key is available to actually re-wrap or unwrap the
     * current pairing's `deviceSecret` in the same step.
     *
     * The whole sequence runs under [NonCancellable]. It used to run on a bare
     * `CoroutineScope(Dispatchers.IO)` created on the spot, with a comment arguing that outliving
     * the Activity was safer than `lifecycleScope` — which correctly identified the risk (a
     * half-applied disable strands `deviceSecret` wrapped with no unwrap path, permanently breaking
     * auth) and then picked a fix that only moved the failure somewhere untracked.
     */
    private fun promptCredentialGatePin(enabling: Boolean) {
        promptForPin(
            titleRes = R.string.security_credential_gate_pin_title,
            onCancelled = { revertCredentialGateSwitch(!enabling) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                if (!resolvePinAttempt(appLockManager.deriveAndCacheCredentialKeys(entered))) {
                    revertCredentialGateSwitch(!enabling)
                    return@launch
                }
                withContext(SecurityWork) {
                    if (enabling) {
                        // Flag first: rewrapPairingIfNeeded checks it as a precondition. A failure
                        // after this point is retried on the next PIN unlock, which is idempotent.
                        appLockStore.setCredentialPinGateEnabled(true)
                        rewrapPairingIfNeeded(this@SecuritySettingsActivity, appLockManager)
                    } else {
                        // Unwrap first, flag second: reversed, an interruption between the two
                        // leaves a wrapped secret that nothing will ever unwrap again.
                        unwrapCurrentPairing()
                        appLockStore.setCredentialPinGateEnabled(false)
                        // Drop the keys we just derived. Leaving them cached meant a pairing saved
                        // later in this same session got re-wrapped behind a gate that is now off,
                        // so no future unlock would ever cache a key to open it again.
                        appLockManager.dropCredentialKeys()
                    }
                }
            }
        }
    }

    /** The inverse of [rewrapPairingIfNeeded] — without this, turning the gate back off would
     *  leave `deviceSecret` stored wrapped with no code path that ever unwraps it. */
    private suspend fun unwrapCurrentPairing() {
        val store = PushRuntime.graph(this).securePairingStore
        val credentialKeys = SecurityRuntime.graph(this).appLockManager.cachedCredentialKeys() ?: return
        val currentPairing = store.pairingSnapshot(credentialKeys) ?: return
        store.savePairing(currentPairing)
    }

    /** Single-field PIN prompt shared by the change-PIN, disable-lock and credential-gate flows. */
    private fun promptForPin(titleRes: Int, onCancelled: () -> Unit = {}, onEntered: (String) -> Unit) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(titleRes)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ -> onEntered(pinField.text.toString()) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setCancelable(false)
            // See [promptEnterAndConfirmPin] and [showSecurely].
            .create()
            .showSecurely()
    }
}
