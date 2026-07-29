package com.urlxl.mail.security

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.addCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.urlxl.mail.MainActivity
import com.urlxl.mail.R
import com.urlxl.mail.applyThemeToActivity
import kotlinx.coroutines.launch

/**
 * Full-screen PIN gate shown whenever [AppLockManager.locked] is true. Biometric unlock layers on
 * top of this; the PIN field here is always present as the fallback.
 *
 * Deliberately NOT a [LockedActivity] — it is the thing the lock redirects *to*. Back is bound to
 * "send the task to the background" rather than `finish()`: finishing used to drop the user
 * straight through onto whatever Activity was underneath, which was the entire lock bypass.
 */
class UnlockActivity : AppCompatActivity() {
    private lateinit var pinField: EditText
    private lateinit var errorText: TextView
    private lateinit var submitButton: Button
    private lateinit var appLockManager: AppLockManager
    private var countdown: CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_unlock)
        applyThemeToActivity(this)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        appLockManager = SecurityRuntime.graph(this).appLockManager

        // Back must never reveal what is behind this screen. Backgrounding the task is the only
        // safe interpretation: the app stays locked and re-gates on the next foreground.
        onBackPressedDispatcher.addCallback(this) { moveTaskToBack(true) }

        pinField = findViewById(R.id.unlockPinField)
        errorText = findViewById(R.id.unlockErrorText)
        submitButton = findViewById(R.id.unlockSubmitButton)
        submitButton.setOnClickListener { attemptUnlock() }

        // Not offered at all when the credential gate is on: the prompt would succeed and then be
        // refused by requirePinForCredentialGate anyway, and asking for a fingerprint the app is
        // about to decline is worse than asking for the PIN in the first place. The check in the
        // success callback stays as the backstop for a gate switched on mid-session.
        val store = SecurityRuntime.graph(this).appLockStore
        if (store.isCredentialPinGateEnabled()) {
            errorText.visibility = View.VISIBLE
            errorText.text = getString(R.string.unlock_pin_required_for_credential_gate)
        } else if (store.isBiometricEnabled()) {
            showBiometricPromptIfAvailable()
        }
    }

    override fun onResume() {
        super.onResume()
        applyRemainingLockout()
    }

    override fun onDestroy() {
        super.onDestroy()
        countdown?.cancel()
    }

    private fun attemptUnlock() {
        val pin = pinField.text.toString()
        // attemptPin runs PBKDF2 and commit()-backed Keystore writes; the button stays disabled
        // for the duration so a double-tap can't burn two attempts against the wipe counter.
        submitButton.isEnabled = false
        lifecycleScope.launch {
            when (val result = appLockManager.attemptPin(pin)) {
                is UnlockAttemptResult.Success -> {
                    // Closes the gap where a background FCM token rotation saved the pairing
                    // unwrapped because no credential key was cached yet in this process, and
                    // migrates any pre-pepper wrap — see rewrapPairingIfNeeded.
                    rewrapPairingIfNeeded(this@UnlockActivity, appLockManager)
                    proceedIntoApp()
                }
                is UnlockAttemptResult.Wiped -> restartToFirstRun()
                is UnlockAttemptResult.WipeFailed -> {
                    // The wipe ran but did not finish, so local data may still be on disk. Say so
                    // rather than showing the same clean first-run screen as a successful wipe —
                    // and still relaunch, since SecurityWipe has left its in-progress marker set
                    // and KyPostApp will retry the whole wipe on the next start.
                    android.util.Log.e("UnlockActivity", "Wipe incomplete: ${result.failedSteps}")
                    restartToFirstRun()
                }
                is UnlockAttemptResult.Rejected -> {
                    pinField.text.clear()
                    errorText.visibility = View.VISIBLE
                    errorText.text = getString(R.string.unlock_wrong_pin)
                    submitButton.isEnabled = true
                    if (result.delayMillis > 0) applyRemainingLockout()
                }
                is UnlockAttemptResult.VerifierUnavailable -> {
                    // The Keystore key behind the stored verifier is gone, so no PIN can ever match
                    // again. Saying "wrong PIN" would send the user round the loop until the wipe
                    // threshold — which this outcome deliberately does not advance — so name the
                    // real problem and the only real remedy.
                    pinField.text.clear()
                    errorText.visibility = View.VISIBLE
                    errorText.text = getString(R.string.security_verifier_unavailable)
                    submitButton.isEnabled = true
                }
            }
        }
    }

    /**
     * Every locked screen finishes itself when it redirects here, so on success there is nothing
     * left in the task to return to. Route through [MainActivity], which already decides between
     * the inbox and the pairing screen.
     */
    private fun proceedIntoApp() {
        startActivity(
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
        )
        finish()
    }

    private fun applyRemainingLockout() {
        val remaining = appLockManager.remainingLockoutMillis()
        countdown?.cancel()
        if (remaining <= 0) {
            submitButton.isEnabled = true
            pinField.isEnabled = true
            return
        }
        submitButton.isEnabled = false
        pinField.isEnabled = false
        countdown = object : CountDownTimer(remaining, 1_000L) {
            override fun onTick(millisUntilFinished: Long) {
                errorText.visibility = View.VISIBLE
                errorText.text = getString(R.string.unlock_locked_out, "${millisUntilFinished / 1_000}s")
            }

            override fun onFinish() {
                submitButton.isEnabled = true
                pinField.isEnabled = true
                errorText.visibility = View.GONE
            }
        }.start()
    }

    /**
     * When "require unlock to receive push/MFA" is on, the PIN is demanded **now** — not deferred
     * to whenever the user next happens to type it.
     *
     * The credential gate wraps `deviceSecret` behind a key only the PIN can derive, and
     * [AppLockManager.unlockWithBiometric] derives nothing. A biometric-only session therefore ran
     * with the gate permanently shut: no authenticated relay call could be made, MFA challenges
     * could not be answered, and every migration hung off a PIN unlock
     * ([rewrapPairingIfNeeded]) simply never ran — for a user whose whole point is that they use
     * the fingerprint reader and not the PIN.
     *
     * The unlock is left *incomplete* rather than granted-then-topped-up: returning true keeps the
     * app locked and hands the user back to the PIN field, so there is no window in which the app
     * is open and the key is still missing. Entering the PIN goes through the ordinary
     * [attemptUnlock] path, which caches the key and runs the rewrap.
     *
     * Returns true when the PIN is now required, i.e. the caller must not proceed.
     */
    private fun requirePinForCredentialGate(): Boolean {
        val store = SecurityRuntime.graph(this).appLockStore
        if (!store.isCredentialPinGateEnabled()) return false
        errorText.visibility = View.VISIBLE
        errorText.text = getString(R.string.unlock_pin_required_for_credential_gate)
        pinField.requestFocus()
        return true
    }

    private fun showBiometricPromptIfAvailable() {
        val biometricManager = BiometricManager.from(this)
        val canAuthenticate = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) return

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.unlock_title))
            .setNegativeButtonText(getString(R.string.unlock_use_pin_button))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    // With the credential gate on, biometric is not a complete unlock and must not
                    // be treated as one — see [requirePinForCredentialGate]. Do NOT unlock first
                    // and ask afterwards: `unlockWithBiometric()` flips the app to unlocked, and
                    // Back from this screen then drops the user into a live app with the PIN never
                    // entered, which is the deferral this exists to remove.
                    if (requirePinForCredentialGate()) return
                    appLockManager.unlockWithBiometric()
                    proceedIntoApp()
                }
                // onAuthenticationError (includes the user tapping "Use PIN") and
                // onAuthenticationFailed both just leave the always-visible PIN field as the
                // fallback — no separate handling needed.
            },
        )
        prompt.authenticate(promptInfo)
    }

    private fun restartToFirstRun() {
        // SecurityWipe already ran (inside AppLockManager.attemptPin's onWipe callback) by the
        // time UnlockAttemptResult.Wiped is returned — this just rebuilds the graphs and
        // relaunches so the app picks up the now-cleared state.
        AppRestart.relaunch(this)
    }
}
