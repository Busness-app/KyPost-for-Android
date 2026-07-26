package com.urlxl.mail.security

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
import com.urlxl.mail.applyThemeToActivity
import com.urlxl.mail.applyTopInsetWithHeader
import com.urlxl.mail.applyWarningCalloutTheme
import com.urlxl.mail.contacts.device.DeviceContactSyncScheduler
import com.urlxl.mail.contacts.device.DeviceContactsRuntime
import com.urlxl.mail.dpToPx
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * "Security" settings: Require Unlock to Open, Hostile Location Protection, and the credential
 * PIN-gate. Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented.
 */
class SecuritySettingsActivity : LockedActivity() {

    private lateinit var appLockStore: AppLockStore
    private lateinit var lockSwitch: SwitchCompat
    private lateinit var changePinButton: Button
    private lateinit var biometricSwitch: SwitchCompat
    private lateinit var hostileLocationSwitch: SwitchCompat
    private lateinit var hostileLocationIntro: TextView
    private lateinit var credentialGateSwitch: SwitchCompat
    private var suppressLockToggleListener = false
    private var suppressCredentialGateListener = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appLockStore = AppLockStore(this)
        setTitle(R.string.security_settings_title)

        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        lockSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_require_unlock_title)
            isChecked = appLockStore.isLockEnabled()
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
            visibility = if (appLockStore.isLockEnabled()) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        container.addViewSpaced(changePinButton, bottomDp = 16)

        biometricSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = appLockStore.isBiometricEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(biometricSwitch, bottomDp = 20)

        val hostileLocationSettings = HostileLocationSettings(this)
        hostileLocationSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_hostile_location_title)
            isChecked = hostileLocationSettings.isEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(hostileLocationSwitch, bottomDp = 4)
        hostileLocationIntro = TextView(this).apply {
            text = if (appLockStore.isLockEnabled()) {
                getString(R.string.security_hostile_location_intro)
            } else {
                getString(R.string.security_hostile_location_requires_lock)
            }
            textSize = 13f
        }
        container.addViewSpaced(hostileLocationIntro, bottomDp = 20)
        hostileLocationSwitch.setOnCheckedChangeListener { _, checked ->
            lifecycleScope.launch {
                withContext(NonCancellable) {
                    if (checked) disableAndPurgeDeviceContactSync()
                    // Both directions need a fresh on-disk kypost_mail.db afterward: enabling must
                    // not leave the pre-toggle disk cache behind, and this is a harmless no-op on
                    // the disable path.
                    SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
                    if (checked) {
                        // "Nothing from before the toggle survives" has to include the plaintext
                        // metadata stores, not just the database — push_state alone held sender and
                        // subject for the last 30 messages.
                        SecurityWipe.deletePlaintextMetadataStores(this@SecuritySettingsActivity)
                    }
                    hostileLocationSettings.setEnabled(checked)
                }
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
        }

        credentialGateSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_credential_gate_title)
            isChecked = appLockStore.isCredentialPinGateEnabled()
            isEnabled = appLockStore.isLockEnabled()
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
        biometricSwitch.setOnCheckedChangeListener { _, checked -> appLockStore.setBiometricEnabled(checked) }

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)
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
            .show()
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
                    // setPin runs PBKDF2; keep it off the main thread like every other PIN path.
                    withContext(NonCancellable) {
                        appLockStore.setPin(pin)
                        appLockStore.setLockEnabled(true)
                    }
                    changePinButton.visibility = View.VISIBLE
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
                val ok = appLockManager.verifyPinThrottled(entered) is UnlockAttemptResult.Success
                if (ok) {
                    promptEnterAndConfirmPin(
                        onConfirmed = { newPin ->
                            lifecycleScope.launch { changePin(oldPin = entered, newPin = newPin) }
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
    private suspend fun changePin(oldPin: String, newPin: String) = withContext(NonCancellable) {
        val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
        val gateEnabled = appLockStore.isCredentialPinGateEnabled()
        val salt = appLockStore.credentialSalt()

        val pairing = if (gateEnabled && salt != null) {
            val oldKeys = CredentialCipher.deriveKeys(oldPin, salt)
            PushRuntime.graph(this@SecuritySettingsActivity).securePairingStore.pairingSnapshot(oldKeys)
        } else {
            null
        }

        appLockStore.setPin(newPin)

        if (gateEnabled && salt != null) {
            // Re-derive under the new PIN and cache, so savePairing's gate-on branch can wrap.
            appLockManager.deriveAndCacheCredentialKeys(newPin)
            if (pairing?.deviceSecret != null) {
                PushRuntime.graph(this@SecuritySettingsActivity).repository.savePairing(pairing)
            }
        }
    }

    private fun promptDisableLock() {
        promptForPin(
            titleRes = R.string.security_confirm_disable_title,
            onCancelled = { revertLockSwitch(true) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                val ok = appLockManager.verifyPinThrottled(entered) is UnlockAttemptResult.Success
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
    private fun disableLock() {
        val hadHostileLocation = HostileLocationSettings(this).isEnabled()
        HostileLocationSettings(this).setEnabled(false)

        if (appLockStore.isCredentialPinGateEnabled()) {
            lifecycleScope.launch {
                withContext(NonCancellable) { SecurityWipe.wipeAndResetApp(this@SecuritySettingsActivity) }
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
            return
        }

        appLockStore.reset()

        if (hadHostileLocation) {
            lifecycleScope.launch {
                withContext(NonCancellable) { SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity) }
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
            return
        }

        changePinButton.visibility = View.GONE
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
                if (!appLockManager.deriveAndCacheCredentialKeys(entered)) {
                    revertCredentialGateSwitch(!enabling)
                    return@launch
                }
                withContext(NonCancellable) {
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
            .show()
    }
}
