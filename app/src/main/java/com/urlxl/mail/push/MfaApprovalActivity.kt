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
    private lateinit var denyButton: Button
    private lateinit var contextText: TextView
    private lateinit var matchGroup: View
    private lateinit var matchChoices: LinearLayout
    private lateinit var matchUnavailable: TextView
    private var challengeId: String = ""
    private var resolveJob: Job? = null
    private var authenticated = false

    /** Set by [burnChallenge]: this challenge is finished on this device regardless of what the
     *  network says, so [resolve] must not re-offer it. */
    private var burned = false

    /** The digits the server is showing in the browser, or blank when this challenge carries no
     *  usable number match — in which case it can only be denied. */
    private var matchDigits: String = ""

    /** The tile order, shuffled once per challenge and kept across recreation. Reshuffling on a
     *  configuration change or a return from the biometric prompt would move the tiles under the
     *  user's finger mid-decision. */
    private var matchOptions: List<String> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_mfa_approval)

        denyButton = findViewById(R.id.btnMfaDeny)
        contextText = findViewById(R.id.mfaApprovalContext)
        matchGroup = findViewById(R.id.mfaMatchGroup)
        matchChoices = findViewById(R.id.mfaMatchChoices)
        matchUnavailable = findViewById(R.id.mfaMatchUnavailable)
        denyButton.setOnClickListener { resolve(approve = false) }

        savedInstanceState?.getStringArray(STATE_MATCH_OPTIONS)?.let { matchOptions = it.toList() }

        if (!adoptChallenge(intent)) return
        requireAuthentication()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArray(STATE_MATCH_OPTIONS, matchOptions.toTypedArray())
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)

        // A different challenge was tapped while this singleTop instance was already on top
        // showing the previous one. Cancel any in-flight resolve() for the old challenge so it
        // can't finish() this screen out from under the new one.
        resolveJob?.cancel()
        resolveJob = null
        // A different challenge means a different choice set and a fresh verdict; neither the
        // previous one's tile order nor its burn may carry over.
        matchOptions = emptyList()
        burned = false

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
     * Renders the number match, which is the only way to approve.
     *
     * There is no bare Approve button any more. The server always mints the value it displays in
     * the browser plus two decoys and verifies the answer itself, so a challenge that does not
     * carry a complete choice set is one this client cannot approve — offering a button that sends
     * no number would spend the server's attempt budget and return a 400 telling the user they got
     * a number wrong that they were never shown. Deny stays available unconditionally.
     */
    private fun setUpNumberMatching(source: Intent) {
        matchDigits = source.getStringExtra(PushNotificationDispatcher.EXTRA_MFA_MATCH_DIGITS).orEmpty()
        val decoys = source.getStringArrayExtra(PushNotificationDispatcher.EXTRA_MFA_DECOY_DIGITS)
            ?.toList()
            .orEmpty()
        // Shuffled once. A restored order is reused so a recreate cannot move the tiles — but only
        // if it still contains this challenge's answer, or every tap would be wrong and the first
        // one would burn a challenge the user answered correctly.
        val options = matchOptions.takeIf { it.isNotEmpty() && matchDigits in it }
            ?: MfaNumberMatch.optionsFor(matchDigits, decoys).orEmpty()
        matchOptions = options

        matchChoices.removeAllViews()
        if (options.isEmpty()) {
            matchDigits = ""
            matchGroup.visibility = View.GONE
            matchUnavailable.visibility = View.VISIBLE
            com.urlxl.mail.applyWarningCalloutTheme(this, matchUnavailable)
            return
        }

        matchUnavailable.visibility = View.GONE
        matchGroup.visibility = View.VISIBLE
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
     * A wrong number burns the challenge. It is not a retry, and it is not merely a deny request.
     *
     * The server keeps a small attempt budget so a legitimate mis-tap is recoverable, but this
     * client deliberately does not use it: letting the user guess again turns a three-way match
     * into a one-in-three chance for an attacker whose victim is tapping blind. So the challenge is
     * struck from the tracker and its notification cancelled *before* the deny is sent, which makes
     * the burn hold even if the deny never reaches the server. Leaving it to the request alone
     * meant that offline, a failed deny re-enabled the tiles and handed back exactly the retry this
     * refuses to allow.
     */
    private fun onMatchChosen(chosen: String) {
        if (!authenticated) return
        if (chosen == matchDigits) {
            resolve(approve = true, chosenDigits = chosen)
            return
        }
        Toast.makeText(this, R.string.mfa_match_wrong, Toast.LENGTH_LONG).show()
        burnChallenge()
        resolve(approve = false)
    }

    /** Makes this challenge unanswerable on this device, whatever the network does next. */
    private fun burnChallenge() {
        PushNotificationDispatcher.cancelMfaChallenge(this, challengeId)
        MfaChallengeTracker(this).clear(challengeId)
        burned = true
    }

    private fun setButtonsEnabled(enabled: Boolean) {
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
     * Authentication is consent for one decision, and it does not survive leaving the screen.
     *
     * This used to be skipped whenever a resolve was in flight, on the reasoning that an in-flight
     * request should not be de-authenticated mid-call. What it actually bought was `authenticated`
     * staying true across a Home press for as long as an OkHttp call with no `callTimeout` can
     * hang — and the in-flight resolve, on failure, then re-enabled every tile on a screen the user
     * had walked away from. The request is unaffected by this; only the ability to submit another
     * one is.
     */
    override fun onStop() {
        super.onStop()
        authenticated = false
        setButtonsEnabled(false)
    }

    /**
     * [chosenDigits] is the value the user tapped. The server is what actually checks it
     * ([MfaResponseClient]); the local comparison in [onMatchChosen] only decides which request to
     * send. Empty on a deny, which the server accepts without a number.
     */
    private fun resolve(approve: Boolean, chosenDigits: String = "") {
        if (!authenticated) return
        setButtonsEnabled(false)
        resolveJob = lifecycleScope.launch {
            val delivered = MfaResponder.respond(applicationContext, challengeId, approve, chosenDigits)
            if (delivered || burned) {
                // A burned challenge is over on this device whether or not the deny landed; there
                // is nothing left here for the user to do.
                finish()
            } else {
                // An undelivered *approve* leaves the challenge genuinely open, and MfaResponder
                // keeps the tracker entry for exactly this — let the user retry.
                resolveJob = null
                setButtonsEnabled(true)
            }
        }
    }

    private companion object {
        const val STATE_MATCH_OPTIONS = "matchOptions"
    }
}
