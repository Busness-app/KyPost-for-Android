package org.kysecurity.mail.security

import android.content.Intent
import android.graphics.Color
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
import org.kysecurity.mail.R
import org.kysecurity.mail.addViewSpaced
import org.kysecurity.mail.applyDangerButtonTheme
import org.kysecurity.mail.applyGhostButtonTheme
import org.kysecurity.mail.applyPanelBackground
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applySectionEyebrowLabel
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.applyWarningCalloutTheme
import org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.dpToPx
import org.kysecurity.mail.getStoredThemePalette
import org.kysecurity.mail.pgp.AndroidIdentitySource
import org.kysecurity.mail.pgp.DeviceEnrollmentActivity
import org.kysecurity.mail.pgp.EnrollmentRow
import org.kysecurity.mail.pgp.EnrollmentSession
import org.kysecurity.mail.pgp.EnrollmentStatus
import org.kysecurity.mail.pgp.EnrollmentTeardown
import org.kysecurity.mail.pgp.EnrollmentVault
import org.kysecurity.mail.pgp.IdentityCheck
import org.kysecurity.mail.pgp.enrollmentRowFor
import org.kysecurity.mail.pgp.hasSecureLockScreen
import org.kysecurity.mail.pgp.openWebmail
import org.kysecurity.mail.pgp.probeEnrollment
import org.kysecurity.mail.pgp.webmailHomeUrl
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The context every security-critical background step in this screen runs on.
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
    val leftBehind = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(context)
    if (leftBehind.isNotEmpty()) {
        android.util.Log.e(
            "SecuritySettings",
            "Enrollment teardown left $leftBehind behind while enabling protection",
        )
    }
    org.kysecurity.mail.pgp.EnrollmentStateWorker.enqueue(context)
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
    private lateinit var wipeThresholdButton: Button
    private lateinit var biometricSwitch: SwitchCompat
    private lateinit var hostileLocationSwitch: SwitchCompat
    private lateinit var hostileLocationIntro: TextView
    private lateinit var credentialGateSwitch: SwitchCompat
    private lateinit var encryptionSectionLabel: TextView
    private lateinit var encryptionCard: LinearLayout

    /** Cards awaiting their rounded panel fill, which can only be applied after
     *  `applyThemeToActivity` has finished flattening every ViewGroup. */
    private val panelCards = mutableListOf<LinearLayout>()
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
        val wipeAfterAttempts: Int?,
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
                    wipeAfterAttempts = graph.appLockStore.wipeAfterAttempts(),
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
            // 16, not the previous 20: the cards carry their own 16dp inset now, and 20 + 16 put
            // content 36dp off the screen edge on a page that is mostly text.
            setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        val lockCard = container.addSection(R.string.security_section_app_lock)

        lockSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_require_unlock_title)
            isChecked = snapshot.lockEnabled
        }
        lockCard.addViewSpaced(lockSwitch, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_require_unlock_intro)), bottomDp = 10)

        changePinButton = Button(this).apply {
            text = getString(R.string.security_change_pin_button)
            visibility = if (snapshot.lockEnabled) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        biometricSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = snapshot.biometricEnabled
            isEnabled = snapshot.lockEnabled
        }
        lockCard.addViewSpaced(biometricSwitch, bottomDp = 10)

        // How long backgrounding is tolerated before the lock re-engages. This existed only as a
        // hardcoded "immediately", which meant the attachment picker, the QR scanner and the
        // webmail handoff each destroyed the screen that launched them — see KyPostApp.onStop.
        val lockGraceSettings = SecurityRuntime.graph(this).appLockSettings
        lockGraceButton = Button(this).apply {
            text = lockGraceButtonLabel(snapshot.graceMillis)
            isEnabled = snapshot.lockEnabled
            setOnClickListener { promptLockGrace(lockGraceSettings) }
        }
        // The two secondary actions share a row. They are peers — both open a picker, neither is the
        // thing you came here to do — and stacking them cost a full button height on a page that does
        // not fit a screen. 0dp width plus weight means "Lock after" simply takes the whole row when
        // "Change PIN" is GONE, which is its state whenever the lock is off.
        val secondaryActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        secondaryActions.addView(
            changePinButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { marginEnd = dpToPx(8) },
        )
        secondaryActions.addView(
            lockGraceButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        lockCard.addViewSpaced(secondaryActions, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_lock_grace_intro)), bottomDp = 8)

        // The wipe threshold is a user choice and has to be visible: it decides whether repeated
        // wrong PINs destroy mail and contacts the app deliberately keeps no backup of.
        wipeThresholdButton = Button(this).apply {
            text = wipeThresholdButtonLabel(snapshot.wipeAfterAttempts)
            isEnabled = snapshot.lockEnabled
            setOnClickListener { promptWipeThreshold() }
        }
        lockCard.addViewSpaced(wipeThresholdButton, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_wipe_threshold_intro)), bottomDp = 0)

        val locationCard = container.addSection(R.string.security_section_location)
        val hostileLocationSettings = SecurityRuntime.graph(this).hostileLocationSettings
        hostileLocationSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_hostile_location_title)
            isChecked = snapshot.hostileLocationEnabled
            isEnabled = snapshot.lockEnabled
        }
        locationCard.addViewSpaced(hostileLocationSwitch, bottomDp = 4)
        hostileLocationIntro = caption(
            if (snapshot.lockEnabled) {
                getString(R.string.security_hostile_location_intro)
            } else {
                getString(R.string.security_hostile_location_requires_lock)
            },
        )
        locationCard.addViewSpaced(hostileLocationIntro, bottomDp = 0)
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
                .create()
                .showSecurely()
        }

        val notificationsCard = container.addSection(R.string.security_section_notifications)
        credentialGateSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_credential_gate_title)
            isChecked = snapshot.credentialGateEnabled
            isEnabled = snapshot.lockEnabled
        }
        notificationsCard.addViewSpaced(credentialGateSwitch, bottomDp = 4)
        notificationsCard.addViewSpaced(
            caption(getString(R.string.security_credential_gate_intro)),
            bottomDp = 10,
        )
        // Always visible regardless of credentialGateSwitch's state: the push-relay exposure this
        // describes exists on every push delivery, on or off — this toggle only ever controlled
        // whether content is withheld while locked, not whether the relay sees it.
        notificationsCard.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_leak_warning)
                textSize = 13f
                setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10))
                applyWarningCalloutTheme(this@SecuritySettingsActivity, this)
            },
            bottomDp = 0,
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
            lifecycleScope.launch {
                withContext(SecurityWork) {
                    appLockStore.setBiometricEnabled(checked)
                    // Switching it off destroys the sealed keys, rather than leaving a
                    // biometric-openable copy of the credential behind a disabled setting. The next
                    // PIN unlock re-seals if it is switched back on.
                    if (!checked) {
                        SecurityRuntime.graph(this@SecuritySettingsActivity).biometricUnlockVault.destroy()
                    }
                }
            }
        }

        // Encrypted mail. Built hidden and filled in asynchronously: deciding the row needs a
        // Keystore probe and (usually) one authenticated request, neither of which may run on the
        // main thread or block the rest of this screen from appearing.
        //
        // The eyebrow and the card are hidden together. A titled empty card on a screen that is
        // otherwise fully populated reads as something failing to load, which is exactly the wrong
        // impression for the one section whose absence is normal (unpaired devices never get it).
        encryptionSectionLabel = TextView(this).apply {
            text = getString(R.string.security_encryption_section)
            applySectionEyebrowLabel(this@SecuritySettingsActivity, this)
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionSectionLabel, bottomDp = 6)
        encryptionCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
            visibility = View.GONE
        }
        panelCards += encryptionCard
        container.addViewSpaced(encryptionCard, bottomDp = 10)
        encryptionRowText = caption("")
        encryptionCard.addViewSpaced(encryptionRowText, bottomDp = 10)
        encryptionActionButton = Button(this).apply { visibility = View.GONE }
        encryptionCard.addViewSpaced(encryptionActionButton, bottomDp = 0)

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)

        // Everything below runs AFTER applyThemeToActivity, which walks the tree and overwrites
        // both of the things this screen's layout depends on. ComposeActivity solved the same
        // problem the same way; this is that precedent, not a new trick.
        //
        // 1. Every ViewGroup, root included, is repainted flat `panel`. Cards left at `panel` on a
        //    `panel` background are invisible, so the scroll surface is repainted `bg` and the cards
        //    keep the rounded `panel` fill — the contrast IS the card.
        val bg = Color.parseColor(getStoredThemePalette(this).bg)
        scrollView.setBackgroundColor(bg)
        container.setBackgroundColor(bg)
        panelCards.forEach { applyPanelBackground(this, it) }

        // 2. Every Button is repainted with the accent-filled primary background. These two are
        //    secondary actions, and three solid accent buttons stacked down a settings page say
        //    everything is equally the thing to do next. Ghost is the style guide's answer.
        applyGhostButtonTheme(this, changePinButton)
        applyGhostButtonTheme(this, lockGraceButton)
        applyGhostButtonTheme(this, wipeThresholdButton)
        refreshEncryptionRow()
    }

    /**
     * A section: an eyebrow label, then a panel card holding the controls.
     *
     * The page was a single flat column of switches, captions and accent buttons — every element at
     * the same visual weight, so nothing said which controls belong together or which one the others
     * depend on. Cards are what the rest of this app already uses for exactly that (Compose's
     * details/message cards, the inbox's keyword bar), and STYLE_GUIDE.md §3 fixes the radius at
     * 14dp across all four KyPost clients.
     *
     * The eyebrow sits OUTSIDE the card, matching web's `.sidebar-section-label` placement.
     */
    private fun LinearLayout.addSection(titleRes: Int, bottomDp: Int = 10): LinearLayout {
        addViewSpaced(
            TextView(this@SecuritySettingsActivity).apply {
                setText(titleRes)
                applySectionEyebrowLabel(this@SecuritySettingsActivity, this)
            },
            bottomDp = 6,
        )
        val card = LinearLayout(this@SecuritySettingsActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
        }
        // Painted later, not here: applyThemeToViewTree repaints every ViewGroup flat `panel` and
        // would flatten the rounding. See the paint pass after applyThemeToActivity.
        panelCards += card
        addViewSpaced(card, bottomDp = bottomDp)
        return card
    }

    /** A control's explanatory line: one step down from the switch it belongs to, never the same
     *  weight. 13sp matches the caption size the rest of this screen already used. */
    private fun caption(text: CharSequence): TextView = TextView(this).apply {
        this.text = text
        textSize = 13f
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
            // The card too, not just its contents: an empty bordered panel is a section that looks
            // broken rather than absent.
            encryptionCard.visibility = View.GONE
            encryptionRowText.visibility = View.GONE
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionSectionLabel.visibility = View.VISIBLE
        encryptionCard.visibility = View.VISIBLE
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
                    //
                    // EnrollmentSession.clear() lives INSIDE this block rather than as a statement
                    // after it, for the exact reason [runSecurityChangeThenReset]'s KDoc calls out
                    // (SecuritySessionReset.kt): NonCancellable protects the block's body, but a
                    // statement placed after `withContext` returns resumes through an ordinary
                    // cancellable continuation. If the Activity is destroyed while destroyAndReport
                    // is in flight, that resume throws CancellationException before ever reaching a
                    // clear() sitting out here — the teardown completes, the clear never runs, and
                    // the account's plaintext PGP private key survives on the heap in a process that
                    // finishing the Activity does not kill.
                    //
                    // try/finally, not a trailing statement, because destroyAndReport itself can
                    // throw: EnrollmentStateWorker.enqueue (reached via destroyAndReport) calls
                    // WorkManager.enqueueUniqueWork with no runCatching, unlike the two steps ahead
                    // of it in the chain. A throw there would otherwise skip the clear the same way
                    // a cancellation would — finally runs it (and lets leftBehind's exception
                    // propagate) unconditionally.
                    val leftBehind = withContext(SecurityWork) {
                        try {
                            EnrollmentTeardown.destroyAndReport(
                                this@SecuritySettingsActivity,
                            )
                        } finally {
                            // The vault and the server-side record are gone, but this process may
                            // still be holding the account's plaintext private key from an earlier
                            // read (EnrollmentSession has exactly one production writer,
                            // VaultOpenerAndroid, and nothing before this cleared it on the unenroll
                            // path). Cleared directly rather than via ProcessState.resetAll():
                            // unenroll is not an account or session boundary — the same account
                            // stays paired — so it must not also discard an in-progress compose
                            // draft or ephemeral attachment plaintext the way a wipe, relaunch or
                            // unpair legitimately does.
                            EnrollmentSession.clear()
                        }
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

    private fun wipeThresholdButtonLabel(attempts: Int?): String = getString(
        R.string.security_wipe_threshold_button,
        if (attempts == null) {
            getString(R.string.security_wipe_threshold_never)
        } else {
            resources.getQuantityString(R.plurals.security_wipe_threshold_attempts, attempts, attempts)
        },
    )

    /**
     * Offers the thresholds in [LockoutPolicy.WIPE_THRESHOLD_CHOICES] plus "never".
     *
     * The dialog states the consequence in the message rather than leaving the user to infer it
     * from a number: the wipe deletes local mail, the synced OS contact rows and this device's
     * pairing, and none of that is recoverable — `allowBackup` and the device-transfer rules are
     * both closed, deliberately.
     */
    private fun promptWipeThreshold() {
        val choices: List<Int?> = LockoutPolicy.WIPE_THRESHOLD_CHOICES + listOf<Int?>(null)
        val labels = choices.map { attempts ->
            if (attempts == null) {
                getString(R.string.security_wipe_threshold_never)
            } else {
                resources.getQuantityString(R.plurals.security_wipe_threshold_attempts, attempts, attempts)
            }
        }.toTypedArray()
        val current = choices.indexOf(appLockStore.wipeAfterAttempts()).takeIf { it >= 0 } ?: 0
        AlertDialog.Builder(this)
            .setTitle(R.string.security_wipe_threshold_dialog_title)
            .setMessage(R.string.security_wipe_threshold_dialog_message)
            .setSingleChoiceItems(labels, current) { dialog, which ->
                val chosen = choices[which]
                lifecycleScope.launch {
                    withContext(SecurityWork) { appLockStore.setWipeAfterAttempts(chosen) }
                    wipeThresholdButton.text = wipeThresholdButtonLabel(chosen)
                }
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
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
            .create()
            .showSecurely()
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
     */
    /** [onConfirmed] takes ownership of the PIN array and must zero it — [usePin] does that. */
    private fun promptEnterAndConfirmPin(onConfirmed: (CharArray) -> Unit, onCancelled: () -> Unit) {
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
                // consumePin, not text.toString(): the PIN never becomes an unzeroable String.
                val pin = pinField.consumePin()
                val confirm = confirmField.consumePin()
                val policyError = pinPolicyMessage(PinPolicy.validate(pin))
                val matches = pin.contentEquals(confirm)
                java.util.Arrays.fill(confirm, ' ')
                when {
                    policyError != null -> {
                        java.util.Arrays.fill(pin, ' ')
                        Toast.makeText(this, policyError, Toast.LENGTH_LONG).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    !matches -> {
                        java.util.Arrays.fill(pin, ' ')
                        Toast.makeText(this, R.string.security_pin_mismatch, Toast.LENGTH_SHORT).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    // onConfirmed owns the array from here and zeroes it when it is done.
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
                    pin.usePin { entered ->
                        // setPin runs PBKDF2 and two commit()-backed Keystore writes — see
                        // [SecurityWork] for why NonCancellable on its own did not move any of it
                        // off the main thread.
                        withContext(SecurityWork) {
                            appLockStore.setPin(entered)
                            appLockStore.setLockEnabled(true)
                            // Seal now rather than at the first unlock, so turning the biometric
                            // switch on below actually offers a fingerprint the first time the app
                            // locks.
                            SecurityRuntime.graph(this@SecuritySettingsActivity)
                                .appLockManager.resealForBiometric(entered)
                        }
                    }
                    changePinButton.visibility = View.VISIBLE
                    lockGraceButton.isEnabled = true
                    wipeThresholdButton.isEnabled = true
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
                                // Both arrays are zeroed here: `entered` has been held across the
                                // second dialog because changePin needs the OLD PIN to unwrap
                                // `deviceSecret` before the verifier is overwritten.
                                val changed = entered.usePin { old ->
                                    newPin.usePin { fresh -> changePin(oldPin = old, newPin = fresh) }
                                }
                                if (!changed) {
                                    Toast.makeText(
                                        this@SecuritySettingsActivity,
                                        R.string.security_change_pin_secret_unreadable,
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        },
                        onCancelled = { java.util.Arrays.fill(entered, ' ') },
                    )
                } else {
                    java.util.Arrays.fill(entered, ' ')
                    Toast.makeText(this@SecuritySettingsActivity, R.string.security_pin_incorrect, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Rotates the PIN, re-wrapping `deviceSecret` in the same step when the credential gate is on.
     */
    private suspend fun changePin(oldPin: CharArray, newPin: CharArray): Boolean = withContext(SecurityWork) {
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
        // The sealed blob still holds the old PIN's keys until this runs.
        appLockManager.resealForBiometric(newPin)

        if (gateEnabled && salt != null) {
            // Re-derive under the new PIN and cache, so savePairing's gate-on branch can wrap.
            appLockManager.deriveAndCacheCredentialKeys(newPin)
            if (pairing?.deviceSecret != null) {
                PushRuntime.graph(this@SecuritySettingsActivity).repository.savePairing(pairing)
            }
        }
        true
    }

    /**
     * `deriveAndCacheCredentialKeys`, not `verifyPinThrottled`.
     *
     * Both run the identical throttled verification; only the former keeps the PIN-derived key. The
     * key is what [disableLock] needs to unwrap `deviceSecret` before the PIN goes away — and
     * verifying without it is precisely how this path ended up destroying the user's mailbox
     * instead: the PIN was checked, the keys were discarded a line later, and the code then
     * concluded the wrapped secret was unrecoverable and ran a full [SecurityWipe].
     */
    private fun promptDisableLock() {
        promptForPin(
            titleRes = R.string.security_confirm_disable_title,
            onCancelled = { revertLockSwitch(true) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                val ok = resolvePinAttempt(entered.usePin { appLockManager.deriveAndCacheCredentialKeys(it) })
                if (ok) disableLock() else revertLockSwitch(true)
            }
        }
    }

    /**
     * Runs once the disabling user has re-verified their current PIN.
     *
     * **Nothing here wipes anything.** This used to run a full [SecurityWipe] whenever the
     * credential gate was on — deleting `kypost_mail.db`, the user's rows in the OS contacts
     * provider, the sealed OpenPGP key and the pairing — behind a dialog whose entire text was
     * "Enter your PIN to turn this off". The stated justification was that a PIN-wrapped
     * `deviceSecret` becomes unrecoverable once the PIN is gone, which is true and irrelevant: the
     * user has *just typed the PIN*, [promptDisableLock] now keeps the key it derives, and
     * [unwrapCurrentPairing] rewrites the secret in the clear before the verifier is cleared. That
     * is the same sequence [promptCredentialGatePin] has always used for the gate's own off-switch.
     *
     * If the unwrap cannot be done, the toggle is refused and nothing is destroyed. Losing access
     * to a credential is the user's problem to solve by re-pairing; it is never a reason for this
     * app to delete their mail.
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

        val appLockManager = SecurityRuntime.graph(this).appLockManager

        if (prior.credentialGate) {
            // Unwrap BEFORE the verifier is cleared, using the key promptDisableLock just derived
            // from the PIN the user typed. Order matters for the same reason it does in
            // promptCredentialGatePin: reversed, an interruption leaves a wrapped secret that
            // nothing can ever unwrap again.
            val unwrapped = withContext(SecurityWork) { unwrapCurrentPairing() }
            if (!unwrapped) {
                // Refuse the toggle and leave every setting as it was. The state reaching here is
                // "we could not read a credential", which is never a reason to delete the user's
                // mail and contacts — which is what this branch used to do.
                withContext(SecurityWork) { settings.setEnabled(prior.hostileLocation) }
                revertLockSwitch(true)
                Toast.makeText(this, R.string.security_disable_lock_unwrap_failed, Toast.LENGTH_LONG).show()
                return
            }
            withContext(SecurityWork) { appLockStore.setCredentialPinGateEnabled(false) }
        }

        withContext(SecurityWork) {
            appLockStore.reset()
            // The sealed keys belong to the PIN that was just discarded. Leaving them would keep a
            // biometric-openable copy of a credential the user has asked the app to forget.
            SecurityRuntime.graph(this@SecuritySettingsActivity).biometricUnlockVault.destroy()
            // Nothing may still hold a PIN-derived key once the PIN is gone: a pairing saved later
            // in this session would otherwise be re-wrapped behind a gate that is now off.
            appLockManager.dropCredentialKeys()
        }

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
        wipeThresholdButton.isEnabled = false
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
            .create()
            .showSecurely()
    }

    private fun confirmDisableCredentialGate() {
        promptCredentialGatePin(enabling = false)
    }

    /**
     * Both directions need the PIN re-entered here (not just "the app happens to be unlocked right
     * now") to guarantee a fresh PIN-derived key is available to actually re-wrap or unwrap the
     * current pairing's `deviceSecret` in the same step.
     */
    private fun promptCredentialGatePin(enabling: Boolean) {
        promptForPin(
            titleRes = R.string.security_credential_gate_pin_title,
            onCancelled = { revertCredentialGateSwitch(!enabling) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                if (!resolvePinAttempt(entered.usePin { appLockManager.deriveAndCacheCredentialKeys(it) })) {
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
                        if (!unwrapCurrentPairing()) {
                            withContext(Dispatchers.Main) {
                                revertCredentialGateSwitch(true)
                                Toast.makeText(
                                    this@SecuritySettingsActivity,
                                    R.string.security_disable_lock_unwrap_failed,
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                            return@withContext
                        }
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

    /**
     * The inverse of [rewrapPairingIfNeeded] — without this, turning the gate back off would leave
     * `deviceSecret` stored wrapped with no code path that ever unwraps it.
     *
     * "No pairing at all" counts as success: there is no secret to strand, so the gate can be
     * turned off freely.
     */
    private suspend fun unwrapCurrentPairing(): Boolean {
        val store = PushRuntime.graph(this).securePairingStore
        if (!store.hasStoredPairing()) return true
        val credentialKeys = SecurityRuntime.graph(this).appLockManager.cachedCredentialKeys()
            ?: return false
        val currentPairing = store.pairingSnapshot(credentialKeys) ?: return false
        if (currentPairing.deviceSecret.isNullOrBlank()) return false
        store.savePairing(currentPairing)
        return true
    }

    /** Single-field PIN prompt shared by the change-PIN, disable-lock and credential-gate flows. */
    private fun promptForPin(titleRes: Int, onCancelled: () -> Unit = {}, onEntered: (CharArray) -> Unit) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(titleRes)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ -> onEntered(pinField.consumePin()) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setCancelable(false)
            // See [promptEnterAndConfirmPin] and [showSecurely].
            .create()
            .showSecurely()
    }
}
