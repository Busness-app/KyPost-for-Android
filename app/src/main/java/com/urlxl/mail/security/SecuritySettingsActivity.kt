package com.urlxl.mail.security

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.CompoundButton
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.urlxl.mail.R
import com.urlxl.mail.addViewSpaced
import com.urlxl.mail.applyThemeToActivity
import com.urlxl.mail.applyTopInsetWithHeader
import com.urlxl.mail.applyWarningCalloutTheme
import com.urlxl.mail.dpToPx
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * "Security" settings screen: Require Unlock to Open (this task), Hostile Location Protection
 * (Task 17), and the credential PIN-gate (Task 18) — see the 2026-07-22 security-hardening
 * spec. Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented.
 */
class SecuritySettingsActivity : AppCompatActivity() {

    private lateinit var appLockStore: AppLockStore
    private lateinit var lockSwitch: Switch
    private lateinit var changePinButton: Button
    private lateinit var biometricSwitch: Switch
    private lateinit var hostileLocationSwitch: Switch
    private lateinit var hostileLocationIntro: TextView
    private lateinit var credentialGateSwitch: Switch
    private var suppressLockToggleListener = false
    private var suppressCredentialGateListener = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE)
        appLockStore = AppLockStore(this)
        setTitle(R.string.security_settings_title)

        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(20), dpToPx(20), dpToPx(20), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        lockSwitch = Switch(this).apply {
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

        // "A 'Change PIN' action appears once enabled" (spec) — only ever visible while lock is
        // on; toggling lock off/on elsewhere in this file must keep this in sync (see
        // promptSetPin/disableLock).
        changePinButton = Button(this).apply {
            text = getString(R.string.security_change_pin_button)
            visibility = if (appLockStore.isLockEnabled()) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        container.addViewSpaced(changePinButton, bottomDp = 16)

        biometricSwitch = Switch(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = appLockStore.isBiometricEnabled()
            isEnabled = appLockStore.isLockEnabled()
        }
        container.addViewSpaced(biometricSwitch, bottomDp = 20)

        val hostileLocationSettings = HostileLocationSettings(this)
        hostileLocationSwitch = Switch(this).apply {
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
                // Both directions need a fresh on-disk kypost_mail.db afterward: enabling must not
                // leave the pre-toggle disk cache behind ("nothing from before the toggle
                // survives" — see the spec's "Toggling on" section), and this is a harmless
                // safety-net no-op on the disable path, since the in-memory DB it's replacing
                // never wrote to this file in the first place. See SecurityWipe.closeAndDeleteDatabase.
                SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
                hostileLocationSettings.setEnabled(checked)
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
        }

        credentialGateSwitch = Switch(this).apply {
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
        // Always visible regardless of credentialGateSwitch's state: the push-relay exposure
        // this describes exists on every push delivery, on or off — this toggle only ever
        // controlled whether content is withheld while locked, not whether the relay sees it.
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

    private fun onLockToggle(checked: Boolean) {
        if (checked) {
            promptSetPin()
        } else {
            promptDisableLock()
        }
    }

    /**
     * Reverts [lockSwitch] to [checked] without re-firing its listener. Used whenever we undo the
     * user's toggle because the set-PIN or disable-lock flow was cancelled or failed — never for
     * the legitimate forward-progress state changes (those call appLockStore directly).
     */
    private fun revertLockSwitch(checked: Boolean) {
        suppressLockToggleListener = true
        lockSwitch.isChecked = checked
        suppressLockToggleListener = false
    }

    /**
     * Reverts [credentialGateSwitch] to [checked] without re-firing its listener — same
     * re-entrancy hazard as [revertLockSwitch], guarded the same way. Used whenever we undo the
     * user's toggle because the PIN prompt was cancelled or the PIN was wrong.
     */
    private fun revertCredentialGateSwitch(checked: Boolean) {
        suppressCredentialGateListener = true
        credentialGateSwitch.isChecked = checked
        suppressCredentialGateListener = false
    }

    /**
     * Shows a two-field "enter 6-digit PIN, then confirm it" dialog — a typo in the single-entry
     * flow this replaced would permanently lock the PIN in with no recovery except 10 deliberate
     * wrong attempts (which wipes) or a reinstall, so the spec requires "enter + confirm" for
     * every *new* PIN, not just the initial one. Shared by [promptSetPin] (turning lock on) and
     * [promptChangePin] (the "Change PIN" action) so both places that mint a brand-new PIN go
     * through the same check. On a match, calls [onConfirmed] with the new 6-digit PIN and closes;
     * on a mismatch or a non-6-digit entry, shows an error and reopens itself so the caller's
     * in-progress state (e.g. [lockSwitch] already flipped on) isn't lost to a stray dismiss —
     * [onCancelled] runs only on an explicit Cancel tap.
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
                when {
                    pin.length != 6 -> onCancelled()
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

    private fun promptSetPin() {
        promptEnterAndConfirmPin(
            onConfirmed = { pin ->
                appLockStore.setPin(pin)
                appLockStore.setLockEnabled(true)
                changePinButton.visibility = View.VISIBLE
                biometricSwitch.isEnabled = true
                hostileLocationSwitch.isEnabled = true
                hostileLocationIntro.text = getString(R.string.security_hostile_location_intro)
                credentialGateSwitch.isEnabled = true
            },
            onCancelled = { revertLockSwitch(false) },
        )
    }

    /** "Change PIN" action (spec: "A 'Change PIN' action appears once enabled"), only reachable
     *  while lock is on (see [changePinButton]'s visibility). Requires the CURRENT PIN first
     *  (same verification as [promptDisableLock]) before minting a new one via the same
     *  enter+confirm flow [promptSetPin] uses — this does not touch [appLockStore]'s
     *  lock-enabled flag or any switch state, only the PIN hash itself. */
    private fun promptChangePin() {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.security_change_pin_title)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ ->
                if (appLockStore.verifyPin(pinField.text.toString())) {
                    promptEnterAndConfirmPin(
                        onConfirmed = { newPin -> appLockStore.setPin(newPin) },
                        onCancelled = {},
                    )
                } else {
                    Toast.makeText(this, R.string.security_pin_incorrect, Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .setCancelable(false)
            .show()
    }

    private fun promptDisableLock() {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.security_confirm_disable_title)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ ->
                if (appLockStore.verifyPin(pinField.text.toString())) {
                    disableLock()
                } else {
                    revertLockSwitch(true)
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> revertLockSwitch(true) }
            .setCancelable(false)
            .show()
    }

    /**
     * Runs once the disabling user has re-verified their current PIN. A full [SecurityWipe]
     * (which also clears pairing, forcing re-pairing) is only actually necessary when the
     * credential gate (toggle 3) was on: that's what leaves a PIN-wrapped `deviceSecret` behind
     * with no way to ever unwrap it again once the PIN is gone. When the gate wasn't on, the spec
     * just wants `AppLockStore`'s PIN/lock state cleared — destroying a perfectly good pairing on
     * a routine settings change would be a worse experience than necessary for no security
     * benefit toggle 1 alone ever promised.
     *
     * Hostile Location Protection is force-disabled either way (it can't be on without lock also
     * being on). If it *was* on, the live `DataGraph` is currently in-memory and must be rebuilt
     * disk-backed now — same as toggling it off directly — which needs a relaunch. If it wasn't,
     * nothing requiring a fresh `DataGraph`/process changed, so this reflects the new (all-off)
     * state directly in the UI instead of relying on a relaunch to redraw it.
     */
    private fun disableLock() {
        val hadHostileLocation = HostileLocationSettings(this).isEnabled()
        HostileLocationSettings(this).setEnabled(false)

        if (appLockStore.isCredentialPinGateEnabled()) {
            lifecycleScope.launch {
                SecurityWipe.wipeAndResetApp(this@SecuritySettingsActivity)
                AppRestart.relaunch(this@SecuritySettingsActivity)
            }
            return
        }

        appLockStore.reset()

        if (hadHostileLocation) {
            lifecycleScope.launch {
                SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
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

    /** Both directions need the PIN re-entered here (not just "the app happens to be unlocked
     *  right now") to guarantee a fresh PIN-derived key is available to actually re-wrap or
     *  unwrap the current pairing's deviceSecret in the same step — see this task's correctness
     *  note about why a confirm-only flow isn't sufficient. */
    private fun promptCredentialGatePin(enabling: Boolean) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.security_credential_gate_pin_title)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ ->
                val appLockManager = SecurityRuntime.graph(this).appLockManager
                if (appLockManager.deriveAndCacheCredentialKey(pinField.text.toString())) {
                    appLockStore.setCredentialPinGateEnabled(enabling)
                    if (enabling) rewrapCurrentPairing() else unwrapCurrentPairing()
                } else {
                    revertCredentialGateSwitch(!enabling)
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> revertCredentialGateSwitch(!enabling) }
            .setCancelable(false)
            .show()
    }

    /** Re-saves the currently-paired credentials wrapped behind the just-derived key — without
     *  this, turning the gate on would only take effect for pairing data saved AFTER this point
     *  (a future re-pair), leaving an existing pairing's deviceSecret unwrapped indefinitely.
     *  Delegates to the shared [rewrapPairingIfNeeded] (also used by [UnlockActivity] after a PIN
     *  unlock) rather than duplicating its preconditions here. Uses a scope that isn't tied to
     *  this Activity's lifecycle — see [unwrapCurrentPairing]'s doc comment for why. */
    private fun rewrapCurrentPairing() {
        CoroutineScope(Dispatchers.IO).launch {
            rewrapPairingIfNeeded(
                this@SecuritySettingsActivity,
                SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager,
            )
        }
    }

    /** The inverse of [rewrapCurrentPairing] — without this, turning the gate back off would leave
     *  deviceSecret stored wrapped with no code path that ever unwraps it, permanently breaking
     *  authentication the next time the app locks (cachedCredentialKey() goes back to null once the
     *  gate reports disabled, and resolveDeviceSecret has no other way to read the wrapped value).
     *  Uses a scope that outlives this Activity rather than `lifecycleScope`: a quick back-press,
     *  config change, or process death right after confirming the PIN would cancel a
     *  lifecycleScope coroutine mid-write, and for this direction specifically that could leave
     *  deviceSecret stuck wrapped with no unwrap path — the exact failure this task exists to
     *  prevent. This is just a couple of fast, local-only SharedPreferences reads/writes, so a
     *  short-lived, fire-and-forget IO scope is enough — no WorkManager needed. */
    private fun unwrapCurrentPairing() {
        CoroutineScope(Dispatchers.IO).launch {
            val securePairingStore = com.urlxl.mail.push.SecurePairingStore(this@SecuritySettingsActivity)
            val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
            val credentialKey = appLockManager.cachedCredentialKey() ?: return@launch
            val currentPairing = securePairingStore.pairingSnapshot(credentialKey) ?: return@launch
            securePairingStore.savePairing(currentPairing)
        }
    }
}
