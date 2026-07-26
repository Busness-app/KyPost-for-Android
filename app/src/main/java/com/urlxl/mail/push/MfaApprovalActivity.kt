package com.urlxl.mail.push

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
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
    private lateinit var contextText: TextView
    private lateinit var matchGroup: View
    private lateinit var matchChoices: LinearLayout
    private var challengeId: String = ""
    private var resolveJob: Job? = null
    private var authenticated = false

    /** The digits the server is showing in the browser, or blank when this server does not
     *  support number matching (in which case the plain Approve button is used). */
    private var matchDigits: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_mfa_approval)

        approveButton = findViewById(R.id.btnMfaApprove)
        denyButton = findViewById(R.id.btnMfaDeny)
        contextText = findViewById(R.id.mfaApprovalContext)
        matchGroup = findViewById(R.id.mfaMatchGroup)
        matchChoices = findViewById(R.id.mfaMatchChoices)
        approveButton.setOnClickListener { resolve(approve = true) }
        denyButton.setOnClickListener { resolve(approve = false) }

        if (!adoptChallenge(intent)) return
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

        if (!adoptChallenge(intent)) return
        // Re-authenticate per challenge: the previous approval's authentication was consent for
        // that decision, not a session that later challenges can ride on.
        authenticated = false
        requireAuthentication()
    }

    /** Returns false (and finishes) if the challenge is blank or was never delivered by a real
     *  push. Also renders the sign-in's context and sets up number matching. */
    private fun adoptChallenge(source: Intent): Boolean {
        val id = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_CHALLENGE_ID).orEmpty()
        if (id.isBlank() || !MfaChallengeTracker(this).isPending(id)) {
            finish()
            return false
        }
        challengeId = id
        renderContext(source)
        setUpNumberMatching(source)
        setButtonsEnabled(false)
        return true
    }

    /**
     * Shows where the sign-in came from.
     *
     * A user who cannot see the origin cannot tell their own login from an attacker's, which makes
     * every other control on this screen ceremony. Where the server has not sent a field, say so
     * explicitly — "Unknown" is information; a blank line reads as "nothing to worry about".
     */
    private fun renderContext(source: Intent) {
        val unknown = getString(R.string.mfa_context_unknown)
        val ip = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_IP).orEmpty()
        val location = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_LOCATION).orEmpty()
        val userAgent = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_USER_AGENT).orEmpty()
        val issuedAt = source.getLongExtra(PushNotificationDispatcher.EXTRA_MFA_ISSUED_AT, 0L)

        val whenText = if (issuedAt > 0L) {
            android.text.format.DateFormat.getTimeFormat(this).format(java.util.Date(issuedAt))
        } else {
            unknown
        }
        contextText.text = listOf(
            getString(R.string.mfa_context_when, whenText),
            getString(R.string.mfa_context_from, location.ifBlank { unknown }),
            getString(R.string.mfa_context_ip, ip.ifBlank { unknown }),
            getString(R.string.mfa_context_device, userAgent.ifBlank { unknown }),
        ).joinToString("\n")
        com.urlxl.mail.applyWarningCalloutTheme(this, contextText)
    }

    /**
     * Replaces the bare Approve button with a three-way number match when the server supplies the
     * digits it is simultaneously showing in the browser.
     *
     * A tap on "Approve" is exactly what an MFA-fatigue attack harvests. A choice between three
     * numbers cannot be made correctly by someone who is not looking at the screen that started
     * the sign-in. Falls back to the plain button when the server sends no digits, so an
     * un-upgraded server keeps working.
     */
    private fun setUpNumberMatching(source: Intent) {
        matchDigits = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_MATCH_DIGITS).orEmpty()
        val decoys = source.getStringArrayExtra(PushNotificationDispatcher.EXTRA_MFA_DECOY_DIGITS)
            ?.toList()
            .orEmpty()
        val options = MfaNumberMatch.optionsFor(challengeId, matchDigits, decoys)

        matchChoices.removeAllViews()
        if (options == null) {
            matchDigits = ""
            matchGroup.visibility = View.GONE
            approveButton.visibility = View.VISIBLE
            return
        }

        matchGroup.visibility = View.VISIBLE
        // The generic Approve button must not remain as a way around the match.
        approveButton.visibility = View.GONE
        options.forEach { value ->
            val button = Button(this).apply {
                text = value
                textSize = 20f
                isEnabled = false
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { marginEnd = (8 * resources.displayMetrics.density).toInt() }
                setOnClickListener { onMatchChosen(value) }
            }
            matchChoices.addView(button)
        }
    }

    /**
     * A wrong number is treated as a denial, not a retry.
     *
     * Letting the user guess again turns a three-way match into a one-in-three chance for an
     * attacker whose victim is tapping blind. The sign-in this challenge belongs to is refused.
     */
    private fun onMatchChosen(chosen: String) {
        if (!authenticated) return
        if (chosen == matchDigits) {
            resolve(approve = true)
            return
        }
        Toast.makeText(this, R.string.mfa_match_wrong, Toast.LENGTH_LONG).show()
        resolve(approve = false)
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        approveButton.isEnabled = enabled
        denyButton.isEnabled = enabled
        for (i in 0 until matchChoices.childCount) {
            matchChoices.getChildAt(i).isEnabled = enabled
        }
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
            if (SecurityRuntime.graph(this).appLockStore.isLockEnabled()) {
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
            val delivered = MfaResponder.respond(applicationContext, challengeId, approve)
            if (delivered) {
                finish()
            } else {
                // The decision never reached the server, so the challenge is still open. Stay put
                // and re-enable the buttons rather than finishing onto a toast the user cannot act
                // on — MfaResponder deliberately leaves the tracker entry intact for this.
                resolveJob = null
                setButtonsEnabled(true)
            }
        }
    }
}
