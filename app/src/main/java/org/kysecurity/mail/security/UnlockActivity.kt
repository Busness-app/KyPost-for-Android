package org.kysecurity.mail.security

import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.addCallback
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.applyThemeToActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
        enableEdgeToEdge()
        setContentView(R.layout.activity_unlock)
        applyThemeToActivity(this)
        window.applySecureFlag()

        appLockManager = SecurityRuntime.graph(this).appLockManager

        // Back must never reveal what is behind this screen. Backgrounding the task is the only
        // safe interpretation: the app stays locked and re-gates on the next foreground.
        onBackPressedDispatcher.addCallback(this) { moveTaskToBack(true) }

        pinField = findViewById(R.id.unlockPinField)
        errorText = findViewById(R.id.unlockErrorText)
        submitButton = findViewById(R.id.unlockSubmitButton)
        submitButton.setOnClickListener { attemptUnlock() }

        // The credential gate is no longer a reason to refuse a fingerprint: biometric unlock now
        // opens the same PIN-derived keys the gate wants, so it is a complete unlock rather than a
        // partial one that has to be topped up with a PIN.
        if (SecurityRuntime.graph(this).appLockStore.isBiometricEnabled()) {
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
                is UnlockAttemptResult.Success -> completeUnlock()
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
     * What a completed unlock owes the rest of the app, whichever credential produced it.
     *
     * Shared by the PIN and biometric paths deliberately. Both now yield the same credential keys,
     * so both can close the gap where a background FCM token rotation saved the pairing unwrapped
     * with nothing cached in this process, and both can migrate a pre-pepper wrap (see
     * [rewrapPairingIfNeeded]). While biometric derived nothing, this work hung off the PIN alone
     * and a user who only ever used the fingerprint reader never ran any of it.
     *
     * [org.kysecurity.mail.pgp.EnrollmentStateWorker] is unique work, so re-enqueueing is idempotent
     * and costs nothing when there is no report owed.
     */
    private suspend fun completeUnlock() {
        rewrapPairingIfNeeded(this, appLockManager)
        org.kysecurity.mail.pgp.EnrollmentStateWorker.enqueue(this)
        proceedIntoApp()
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
     * Offers the fingerprint only when there is something for it to open.
     *
     * [BiometricUnlockVault.prepareUnlock] returns null on a device that has never completed a PIN
     * unlock since this feature landed, and on one whose key the OS destroyed because a biometric
     * was enrolled. Both leave the always-visible PIN field as the only route, and the next PIN
     * unlock re-seals — so the fallback repairs itself and needs no user-facing recovery step.
     *
     * The vault call is Keystore and disk work, hence the hop off the main thread.
     */
    private fun showBiometricPromptIfAvailable() {
        if (BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            return
        }

        lifecycleScope.launch {
            val unlock = withContext(Dispatchers.IO) {
                SecurityRuntime.graph(this@UnlockActivity).biometricUnlockVault.prepareUnlock()
            } ?: return@launch

            // A prompt requested after the FragmentManager has saved its state is silently dropped
            // by BiometricPrompt with no callback ever — see AndroidVaultOpener, which closes the
            // same race in the same place. Checked here, on Main, immediately before authenticate().
            if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || supportFragmentManager.isStateSaved) {
                return@launch
            }
            authenticate(unlock)
        }
    }

    private fun authenticate(unlock: BiometricUnlock) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.unlock_title))
            .setNegativeButtonText(getString(R.string.unlock_use_pin_button))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                /**
                 * The authentication is *used*, not merely observed. The cipher handed back here is
                 * the one the Keystore refused to operate until the user authenticated, and the keys
                 * it opens are the same ones a PIN unlock derives — so there is no longer a version
                 * of this callback that grants access without producing a secret.
                 */
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val cipher = result.cryptoObject?.cipher
                    val keys = cipher?.let { CredentialEnvelope.open(unlock.sealed, it) }
                    if (keys == null) {
                        // The blob and the key have gone out of step. Nothing here is recoverable by
                        // trying again, and the PIN both unlocks and re-seals.
                        errorText.visibility = View.VISIBLE
                        errorText.text = getString(R.string.unlock_biometric_unavailable)
                        pinField.requestFocus()
                        return
                    }
                    appLockManager.unlockWithBiometric(keys)
                    lifecycleScope.launch { completeUnlock() }
                }
                // onAuthenticationError (includes the user tapping "Use PIN") and
                // onAuthenticationFailed both just leave the always-visible PIN field as the
                // fallback — no separate handling needed.
            },
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(unlock.cipher))
    }

    private fun restartToFirstRun() {
        // SecurityWipe already ran (inside AppLockManager.attemptPin's onWipe callback) by the
        // time UnlockAttemptResult.Wiped is returned — this just rebuilds the graphs and
        // relaunches so the app picks up the now-cleared state.
        AppRestart.relaunch(this)
    }
}
