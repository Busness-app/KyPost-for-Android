package com.urlxl.mail.push

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.urlxl.mail.R
import com.urlxl.mail.security.AppLockStore
import com.urlxl.mail.security.SecurityRuntime
import com.urlxl.mail.security.UnlockAttemptResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * The only place an MFA challenge can be approved or denied.
 *
 * Not a [com.urlxl.mail.security.LockedActivity]: it has to be reachable while the app is locked,
 * because that is exactly when a sign-in prompt tends to arrive. Instead it authenticates in place
 * — device biometric or device credential — before either button does anything. Approving a
 * sign-in is the single highest-value action in this app, and it used to be available as a
 * notification action that fired straight from the lock screen with no authentication whatsoever.
 *
 * The [MfaChallengeTracker] check is enforced here too, not just in
 * [com.urlxl.mail.MainActivity]: a challenge id that never arrived via a real push must not be
 * actionable, however this screen was reached.
 */
class MfaApprovalActivity : AppCompatActivity() {
    private lateinit var approveButton: Button
    private lateinit var denyButton: Button
    private var challengeId: String = ""
    private var resolveJob: Job? = null
    private var authenticated = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_mfa_approval)

        approveButton = findViewById(R.id.btnMfaApprove)
        denyButton = findViewById(R.id.btnMfaDeny)
        approveButton.setOnClickListener { resolve(approve = true) }
        denyButton.setOnClickListener { resolve(approve = false) }

        if (!adoptChallenge(intent.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_CHALLENGE_ID).orEmpty())) return
        requireAuthentication()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)

        // A different challenge was tapped while this singleTop instance was already on top
        // showing the previous one. Cancel any in-flight resolve() for the old challenge so it
        // can't finish() this screen out from under the new one.
        resolveJob?.cancel()
        resolveJob = null

        if (!adoptChallenge(intent.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_CHALLENGE_ID).orEmpty())) return
        // Re-authenticate per challenge: the previous approval's authentication was consent for
        // that decision, not a session that later challenges can ride on.
        authenticated = false
        requireAuthentication()
    }

    /** Returns false (and finishes) if [id] is blank or was never delivered by a real push. */
    private fun adoptChallenge(id: String): Boolean {
        if (id.isBlank() || !MfaChallengeTracker(this).isPending(id)) {
            finish()
            return false
        }
        challengeId = id
        setButtonsEnabled(false)
        return true
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        approveButton.isEnabled = enabled
        denyButton.isEnabled = enabled
    }

    /**
     * Gates both buttons behind a biometric or device-credential check, falling back to this app's
     * own PIN when the device has neither.
     *
     * `canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` returns success whenever a device
     * credential is enrolled, even with no usable sensor, so the fallback branch is reached only on
     * a device with **no screen lock at all**. That used to enable both buttons outright, on the
     * argument that anyone holding such a device already has unrestricted access. That argument is
     * false here: this app maintains its own PIN, lockout ladder and wipe threshold, and this screen
     * is deliberately exempt from the app lock, so the PIN was the only thing an attacker would
     * otherwise have had to defeat — on what this file itself calls the highest-value action in the
     * app. Fall back to that PIN, and fail open only when there is no authenticator of any kind.
     */
    private fun requireAuthentication() {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            if (AppLockStore(this).isLockEnabled()) {
                promptAppLockPin()
            } else {
                authenticated = true
                setButtonsEnabled(true)
            }
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.mfa_auth_title))
            .setSubtitle(getString(R.string.mfa_auth_subtitle))
            .setAllowedAuthenticators(authenticators)
            .build()

        BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    authenticated = true
                    setButtonsEnabled(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // Cancelled or unavailable: leave the decision unmade rather than falling
                    // through to enabled buttons.
                    Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                    finish()
                }
            },
        ).authenticate(promptInfo)
    }

    /**
     * The app-lock PIN as the authenticator of last resort, routed through
     * [AppLockManager.verifyPinThrottled] so the lockout ladder and the wipe threshold apply here
     * exactly as they do on the unlock screen — an approval prompt must not become an unthrottled
     * PIN oracle.
     */
    private fun promptAppLockPin() {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        android.app.AlertDialog.Builder(this)
            .setTitle(R.string.mfa_auth_title)
            .setMessage(R.string.mfa_auth_subtitle)
            .setView(pinField)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                lifecycleScope.launch {
                    val manager = SecurityRuntime.graph(this@MfaApprovalActivity).appLockManager
                    val ok = manager.verifyPinThrottled(pinField.text.toString()) is UnlockAttemptResult.Success
                    if (ok) {
                        authenticated = true
                        setButtonsEnabled(true)
                    } else {
                        Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                        finish()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    /**
     * Re-authenticate per challenge, as this file's `onNewIntent` contract already intends. Without
     * this the activity kept `authenticated = true` across a Home press, and — not being
     * `excludeFromRecents` — could be resumed from Recents by anyone within the tracker's
     * five-minute window and approved with no further check.
     */
    override fun onStop() {
        super.onStop()
        if (resolveJob == null) {
            authenticated = false
            setButtonsEnabled(false)
        }
    }

    private fun resolve(approve: Boolean) {
        if (!authenticated) return
        setButtonsEnabled(false)
        resolveJob = lifecycleScope.launch {
            MfaResponder.respond(applicationContext, challengeId, approve)
            finish()
        }
    }
}
