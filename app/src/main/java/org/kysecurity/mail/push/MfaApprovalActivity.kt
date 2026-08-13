package org.kysecurity.mail.push

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import org.kysecurity.mail.security.applySecureFlag
import org.kysecurity.mail.security.AppLockStore
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.resolvePinAttempt
import org.kysecurity.mail.security.showSecurely
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * The only place an MFA challenge can be approved or denied.
 *
 * Not a [org.kysecurity.mail.security.LockedActivity]: it has to be reachable while the app is locked,
 * because that is exactly when a sign-in prompt tends to arrive. Instead it authenticates in place
 * — device biometric or device credential — before either button does anything. Approving a
 * sign-in is the single highest-value action in this app, and it used to be available as a
 * notification action that fired straight from the lock screen with no authentication whatsoever.
 *
 * The [MfaChallengeTracker] check is enforced here too, not just in
 * [org.kysecurity.mail.MainActivity]: a challenge id that never arrived via a real push must not be
 * actionable, however this screen was reached.
 */
class MfaApprovalActivity : AppCompatActivity() {
    private lateinit var denyButton: Button
    private lateinit var contextText: TextView
    private lateinit var matchGroup: View
    private lateinit var matchChoices: LinearLayout
    private lateinit var matchUnavailable: TextView
    /** The whole challenge, not just its id: [MfaResponder] needs it to put the notification back
     *  when a response fails to reach the server. Null before [adoptChallenge] has accepted one. */
    private var payload: MfaChallengePayload? = null
    private val challengeId: String get() = payload?.challengeId.orEmpty()
    private var resolveJob: Job? = null
    private var authenticated = false

    /** A prompt is on screen and has not answered yet. Without this, [onStart] fires immediately
     *  after `onCreate` has already started one — `authenticated` is still false because the prompt
     *  is asynchronous — and the user gets two stacked biometric dialogs on every cold start. */
    private var authInFlight = false

    /** The app-lock PIN dialog while it is showing. Held so [onStop] can dismiss it — see
     *  [promptAppLockPin]. */
    private var pinDialog: android.app.AlertDialog? = null

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

    /**
     * The credential keys derived when the user verified their PIN for *this* decision, when the
     * credential gate is on. Null when the gate is off, where the stored secret needs no key.
     *
     * Held here rather than re-read from [org.kysecurity.mail.security.AppLockManager.cachedCredentialKeys]
     * at send time: this screen runs on a locked app (a notification tap does not unlock anything),
     * and that accessor returns null while locked by design — so the response died locally with
     * "Device is not registered yet" and neither approve nor deny ever reached the server. Cleared
     * in [onStop] alongside `authenticated`, so it lives exactly as long as the consent does.
     */
    private var decisionKeys: org.kysecurity.mail.security.CredentialKeys? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.applySecureFlag()
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
        payload = null

        if (!adoptChallenge(intent)) return
        // Re-authenticate per challenge: the previous approval's authentication was consent for
        // that decision, not a session that later challenges can ride on.
        authenticated = false
        authInFlight = false
        requireAuthentication()
    }

    /** Returns false (and finishes) if the challenge is malformed or was never delivered by a real
     *  push. Also renders the sign-in's context and sets up number matching. */
    private fun adoptChallenge(source: Intent): Boolean {
        val adopted = PushNotificationDispatcher.payloadFrom(source)
        if (adopted == null || !PushRuntime.graph(this).mfaChallengeTracker.isPending(adopted.challengeId)) {
            // Say why. A challenge can legitimately stop being pending — it expired, it was already
            // answered, or a flood of new ones evicted it from the tracker's bounded set — and
            // finishing in silence made a tapped notification look like a broken app.
            Toast.makeText(this, R.string.mfa_challenge_unavailable, Toast.LENGTH_LONG).show()
            finish()
            return false
        }
        payload = adopted
        renderContext(adopted)
        setUpNumberMatching(adopted)
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
    private fun renderContext(source: MfaChallengePayload) {
        val unknown = getString(R.string.mfa_context_unknown)
        val whenText = if (source.issuedAtEpochMs > 0L) {
            android.text.format.DateFormat.getTimeFormat(this).format(java.util.Date(source.issuedAtEpochMs))
        } else {
            unknown
        }
        contextText.text = listOf(
            getString(R.string.mfa_context_when, whenText),
            getString(R.string.mfa_context_ip, source.ipAddress.ifBlank { unknown }),
            getString(R.string.mfa_context_device, source.userAgent.ifBlank { unknown }),
        ).joinToString("\n")
        org.kysecurity.mail.applyWarningCalloutTheme(this, contextText)
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
    private fun setUpNumberMatching(source: MfaChallengePayload) {
        matchDigits = source.matchDigits
        val decoys = source.decoyDigits
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
            org.kysecurity.mail.applyWarningCalloutTheme(this, matchUnavailable)
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
        PushRuntime.graph(this).mfaChallengeTracker.clear(challengeId)
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
     * **The app-lock PIN comes first whenever the credential gate is on**, because answering a
     * challenge needs the PIN-derived key: [MfaResponder] authenticates with `deviceSecret`, which
     * [org.kysecurity.mail.push.PushRepository.pairingForAuthenticatedCall] can only unwrap from a
     * cached credential key, and a device credential is not that key. Authenticating with a
     * fingerprint here and then discovering the response cannot be sent is a decision taken and
     * silently dropped, on the highest-value action in this app.
     *
     * The fallback used to be reached on *any* status other than `BIOMETRIC_SUCCESS`, on the
     * argument that `canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` succeeds whenever a
     * device credential is enrolled, so anything else means no screen lock at all. It does not:
     * `BIOMETRIC_ERROR_HW_UNAVAILABLE` (sensor temporarily down) and `BIOMETRIC_STATUS_UNKNOWN`
     * (documented as indeterminate, with the advice to call `authenticate()` anyway) both land
     * there on a device that *does* have a screen lock — and with this app's own PIN unset, both
     * buttons went live with no authentication whatsoever. Only the three statuses that definitely
     * mean "there is no authenticator to use" take the fallback now; everything else shows the
     * prompt and lets [BiometricPrompt.AuthenticationCallback.onAuthenticationError] finish the
     * screen.
     */
    private fun requireAuthentication() {
        authInFlight = true

        // The gate is on: nothing but the PIN produces a usable credential, so ask for it directly
        // rather than collecting a device credential that cannot answer the challenge.
        if (credentialGateNeedsPin()) {
            promptAppLockPin()
            return
        }

        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (mfaHasNoAuthenticator(BiometricManager.from(this).canAuthenticate(authenticators))) {
            if (SecurityRuntime.graph(this).appLockStore.isLockEnabled()) {
                promptAppLockPin()
            } else {
                // Genuinely nothing to authenticate against: no sensor, no enrolled device
                // credential, and no app-lock PIN configured either.
                authInFlight = false
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
                    authInFlight = false
                    authenticated = true
                    setButtonsEnabled(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    authInFlight = false
                    // Cancelled or unavailable: leave the decision unmade rather than falling
                    // through to enabled buttons.
                    Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                    finish()
                }
            },
        ).authenticate(promptInfo)
    }

    /** The credential gate is on and this process has no PIN-derived key, so only the app-lock PIN
     *  can make this challenge answerable. */
    private fun credentialGateNeedsPin(): Boolean {
        val graph = SecurityRuntime.graph(this)
        if (!graph.appLockStore.isLockEnabled()) return false
        if (!graph.appLockStore.isCredentialPinGateEnabled()) return false
        return graph.appLockManager.cachedCredentialKeys() == null
    }

    /**
     * The app-lock PIN, routed through [AppLockManager] so the lockout ladder and the wipe
     * threshold apply here exactly as they do on the unlock screen — an approval prompt must not
     * become an unthrottled PIN oracle.
     *
     * Uses [AppLockManager.deriveAndCacheCredentialKeys] rather than
     * [AppLockManager.verifyPinThrottled] when the credential gate is on: both run the same
     * throttled verification, but only the former caches the key that
     * [MfaResponder] needs to unwrap `deviceSecret`. Verifying alone would authenticate the user
     * and still leave the response unsendable.
     *
     * The dialog is **held and dismissed in [onStop]**. It is `setCancelable(false)` and survives
     * backgrounding, while `onStop` clears `authInFlight` — so returning to the screen ran
     * [requireAuthentication] again and stacked a second identical prompt on the first, leaking the
     * first's window and letting two dismissals burn two attempts against the wipe threshold for
     * what the user saw as one prompt.
     */
    private fun promptAppLockPin() {
        pinDialog?.dismiss()
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        val gateNeedsPin = credentialGateNeedsPin()
        pinDialog = android.app.AlertDialog.Builder(this)
            .setTitle(R.string.mfa_auth_title)
            .setMessage(if (gateNeedsPin) R.string.mfa_auth_subtitle_pin_required else R.string.mfa_auth_subtitle)
            .setView(pinField)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                lifecycleScope.launch {
                    val manager = SecurityRuntime.graph(this@MfaApprovalActivity).appLockManager
                    val pin = pinField.text.toString()
                    val attempt = if (gateNeedsPin) {
                        manager.deriveAndCacheCredentialKeys(pin)
                    } else {
                        manager.verifyPinThrottled(pin)
                    }
                    // resolvePinAttempt, not `is Success`: the wipe threshold applies here too, and
                    // reporting a completed destructive wipe as "authentication required" told the
                    // user nothing about what had just happened to their data. See [PinGate].
                    val ok = resolvePinAttempt(attempt)
                    authInFlight = false
                    pinDialog = null
                    if (ok) {
                        // Captured for the life of this authenticated decision. Reading the key back
                        // later through cachedCredentialKeys() returns null, because a notification
                        // tap does not unlock the app and that accessor gates on lock state — which
                        // is why every gated approve and deny used to fail with "Device is not
                        // registered yet" without a request ever leaving the device.
                        if (gateNeedsPin) decisionKeys = manager.credentialKeysForDecision()
                        authenticated = true
                        setButtonsEnabled(true)
                    } else {
                        Toast.makeText(this@MfaApprovalActivity, R.string.mfa_auth_required, Toast.LENGTH_SHORT).show()
                        finish()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                authInFlight = false
                pinDialog = null
                finish()
            }
            .setCancelable(false)
            .create()
            .showSecurely()
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
        authInFlight = false
        // Dropped with the authentication that produced them: the key is consent for one decision
        // taken on this screen, and it must not outlive the user's presence on it.
        decisionKeys = null
        // Torn down with the authentication it belongs to. Leaving it up while clearing
        // `authInFlight` is what let [onStart] stack a second one on top of it.
        pinDialog?.dismiss()
        pinDialog = null
        setButtonsEnabled(false)
    }

    /**
     * Re-authenticates on the way back, because [onStop] de-authenticates on the way out.
     *
     * Without this the screen was a dead end: `authenticated` was cleared by [onStop] and nothing
     * ever set it again — [requireAuthentication] ran only from `onCreate` and [onNewIntent]. A
     * user who took a phone call mid-decision came back to buttons that silently did nothing,
     * because [onMatchChosen] and [resolve] both bail on `!authenticated`. On the screen this file
     * calls the highest-value action in the app.
     *
     * Skipped while a resolve is in flight — that decision is already made and submitted; prompting
     * for a fingerprint on top of it would be asking consent for something already sent.
     */
    override fun onStart() {
        super.onStart()
        if (authenticated || authInFlight || payload == null || resolveJob?.isActive == true) return
        requireAuthentication()
    }

    /**
     * [chosenDigits] is the value the user tapped. The server is what actually checks it
     * ([MfaResponseClient]); the local comparison in [onMatchChosen] only decides which request to
     * send. Empty on a deny, which the server accepts without a number.
     */
    private fun resolve(approve: Boolean, chosenDigits: String = "") {
        if (!authenticated) return
        val current = payload ?: return
        setButtonsEnabled(false)
        resolveJob = lifecycleScope.launch {
            val delivered =
                MfaResponder.respond(applicationContext, current, approve, chosenDigits, decisionKeys)
            if (delivered || burned) {
                // A burned challenge is over on this device whether or not the deny landed; there
                // is nothing left here for the user to do.
                finish()
                return@launch
            }
            // An undelivered *approve* leaves the challenge genuinely open, and MfaResponder
            // keeps the tracker entry and re-posts the notification for exactly this — let the
            // user retry.
            resolveJob = null
            // Only if this screen is still authenticated. `lifecycleScope` cancels on DESTROY, not
            // on STOP, so a slow request that fails after the user pressed Home used to re-enable
            // every tile on a stopped screen — which then stayed enabled and inert on the way back,
            // since onStop had already cleared `authenticated`. onStart re-prompts instead.
            if (authenticated) setButtonsEnabled(true)
        }
    }

    private companion object {
        const val STATE_MATCH_OPTIONS = "matchOptions"
    }
}

/**
 * Whether a [BiometricManager.canAuthenticate] status means there is genuinely **no authenticator
 * to use**, as opposed to one that could not be checked right now.
 *
 * [MfaApprovalActivity] used to treat everything except `BIOMETRIC_SUCCESS` as the former and, with
 * this app's own PIN unset, enable approve and deny with no authentication at all. The premise —
 * "`canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)` succeeds whenever a device credential is
 * enrolled, so anything else means no screen lock" — is not what the API guarantees:
 *
 * - `BIOMETRIC_ERROR_HW_UNAVAILABLE` is *temporary* (sensor busy or powered down).
 * - `BIOMETRIC_STATUS_UNKNOWN` is documented as indeterminate, with the explicit advice to call
 *   `authenticate()` anyway.
 * - `BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED` means the sensor is untrusted, not that the device
 *   credential is gone.
 *
 * All three occur on devices that *do* have a screen lock, so all three must show the prompt and
 * let its error callback fail the screen closed. Only the three below are terminal.
 *
 * Top-level and Context-free so the classification is unit-testable on the JVM — the same reason
 * [MfaNumberMatch] and [mfaChallengeIsFresh] live outside their callers.
 */
internal fun mfaHasNoAuthenticator(canAuthenticateStatus: Int): Boolean = when (canAuthenticateStatus) {
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
    BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
    -> true
    else -> false
}
