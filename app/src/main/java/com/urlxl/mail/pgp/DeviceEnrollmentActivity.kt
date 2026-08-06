package com.urlxl.mail.pgp

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.urlxl.mail.R
import com.urlxl.mail.applyGhostButtonTheme
import com.urlxl.mail.applyPrimaryButtonTheme
import com.urlxl.mail.applyThemeToActivity
import com.urlxl.mail.applyTopInsetWithHeader
import com.urlxl.mail.security.LockedActivity
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import kotlin.coroutines.resume

/**
 * The enrollment ceremony's screen: renders [EnrollmentUiState] and owns the one piece the pure
 * orchestrator cannot — `BiometricPrompt`, which is Activity-bound.
 *
 * A dedicated Activity rather than a section of `SecuritySettingsActivity` (706 lines, and where the
 * `NonCancellable` continuation bug lived) or `PgpKeyActivity` (466). Neither should grow a
 * multi-minute stateful ceremony.
 */
class DeviceEnrollmentActivity : LockedActivity() {

    private val viewModel: DeviceEnrollmentViewModel by viewModels()

    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var codeText: TextView
    private lateinit var expiryText: TextView
    private lateinit var checkAgainButton: Button
    private lateinit var closeButton: Button

    private var countdown: Job? = null

    /**
     * Where the AES-GCM `doFinal` and the `commit()`-backed store run.
     *
     * Not the main thread — `EnrollmentVault.store` is a Keystore round trip plus a synchronous
     * write into `EncryptedSharedPreferences`, which is exactly the work `SecuritySettingsActivity`'s
     * own KDoc records having wrongly run on the UI thread. Not `lifecycleScope` either: that is
     * cancelled when this Activity is destroyed, and a seal cancelled halfway leaves a continuation
     * nothing ever resumes, hanging the ceremony. A plain executor is independent of both.
     */
    private val sealExecutor = Executors.newSingleThreadExecutor()

    /**
     * The `VaultSealer` handed to the ViewModel.
     *
     * An anonymous object rather than making this Activity implement the interface: `VaultSealer` is
     * `internal`, and a public class may not widen an internal supertype.
     */
    private val vaultSealer = object : VaultSealer {
        override suspend fun seal(plaintext: ByteArray): SealOutcome =
            suspendCancellableCoroutine { continuation ->
                val vault = EnrollmentVault(applicationContext)

                // The authority on "is there a secure lock screen", and the point where a key is
                // legitimately generated. Returns false by design without one.
                if (!vault.ensureKey()) {
                    continuation.resume(SealOutcome.NoSecureLockScreen)
                    return@suspendCancellableCoroutine
                }
                val cipher = vault.sealCipher()
                if (cipher == null) {
                    continuation.resume(SealOutcome.Failed("The vault cipher could not be created"))
                    return@suspendCancellableCoroutine
                }

                val prompt = BiometricPrompt(
                    this@DeviceEnrollmentActivity,
                    ContextCompat.getMainExecutor(this@DeviceEnrollmentActivity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            val authenticated = result.cryptoObject?.cipher
                            if (authenticated == null) {
                                if (continuation.isActive) {
                                    continuation.resume(
                                        SealOutcome.Failed("No authenticated cipher was returned"),
                                    )
                                }
                                return
                            }
                            // A late result can arrive after this Activity's own onDestroy has
                            // already shut down its sealExecutor: on rotation, BiometricPrompt's
                            // pending operation is delivered to whichever callback was last
                            // registered with the (config-change-surviving) BiometricViewModel,
                            // which is this one if the new Activity never re-authenticated.
                            // execute() on a shut-down executor throws RejectedExecutionException
                            // synchronously on the caller's thread (the main thread, here) — that
                            // must become a SealOutcome, not an uncaught crash.
                            try {
                                sealExecutor.execute {
                                    val outcome = runCatching {
                                        val ciphertext = authenticated.doFinal(plaintext)
                                        vault.store(authenticated.iv, ciphertext)
                                        SealOutcome.Sealed
                                    }.getOrElse { SealOutcome.Failed(it.message ?: "The seal failed") }
                                    if (continuation.isActive) continuation.resume(outcome)
                                }
                            } catch (e: RejectedExecutionException) {
                                if (continuation.isActive) {
                                    continuation.resume(
                                        SealOutcome.Failed("The seal executor was no longer available"),
                                    )
                                }
                            }
                        }

                        /** Includes the user dismissing the prompt AND this Activity being
                         *  destroyed under it — a rotation lands here. The ceremony treats both the
                         *  same: back to the code, nothing destroyed. */
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (continuation.isActive) continuation.resume(SealOutcome.Cancelled)
                        }

                        // onAuthenticationFailed is a non-matching finger. The prompt stays up and
                        // the user tries again; there is nothing to resume.
                    },
                )

                // DEVICE_CREDENTIAL is allowed because the vault key itself allows it — see
                // EnrollmentVault's KDoc on why biometric-only would invalidate the key on every
                // fingerprint change. With DEVICE_CREDENTIAL in the set, setNegativeButtonText must
                // NOT be called: BiometricPrompt throws if both are given.
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(getString(R.string.enrollment_auth_title))
                    .setSubtitle(getString(R.string.enrollment_auth_subtitle))
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
                continuation.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
            }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run.
        if (redirectedToUnlock) return
        setContentView(R.layout.activity_device_enrollment)
        setTitle(R.string.enrollment_title)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.deviceEnrollmentRoot))

        headline = findViewById(R.id.enrollmentHeadline)
        detail = findViewById(R.id.enrollmentDetail)
        codeText = findViewById(R.id.enrollmentCode)
        expiryText = findViewById(R.id.enrollmentExpiry)
        checkAgainButton = findViewById(R.id.btnEnrollmentCheckAgain)
        closeButton = findViewById(R.id.btnEnrollmentClose)

        checkAgainButton.setOnClickListener { viewModel.checkAgain() }
        closeButton.setOnClickListener { finish() }

        // Installed here rather than in onStart: the ceremony may reach the seal at any moment, and
        // a null sealer resolves as a cancel.
        viewModel.installSealer(vaultSealer)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                combine(viewModel.state, viewModel.idle) { state, idle -> state to idle }
                    .collect { (state, idle) -> render(state, idle) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, checkAgainButton)
        applyGhostButtonTheme(this, closeButton)
    }

    override fun onDestroy() {
        // Only clear the slot if this Activity is still the one in it. On a rotation the new
        // Activity's onCreate runs BEFORE the old one's onDestroy, and isChangingConfigurations()
        // is true for exactly that case — so skipping the clear there is what stops an
        // unconditional null from uninstalling the incoming sealer and turning the next prompt
        // into a cancel. Every other path out of this screen (finish(), the app lock, the OS
        // reclaiming the process) is not a configuration change, so the clear still runs.
        if (!isChangingConfigurations()) {
            viewModel.installSealer(null)
        }
        sealExecutor.shutdown()
        super.onDestroy()
    }

    private fun render(state: EnrollmentUiState, idle: Boolean) {
        countdown?.cancel()
        countdown = null

        val showingCode = state is EnrollmentUiState.ShowingCode ||
            state is EnrollmentUiState.WaitingTimedOut

        // FLAG_KEEP_SCREEN_ON while the code is up. Without it the screen times out while the user
        // is typing into their browser, which backgrounds the app, which starts the lock grace —
        // and the user comes back to an unlock prompt with the ceremony destroyed.
        if (showingCode) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        val code = when (state) {
            is EnrollmentUiState.ShowingCode -> state.code to state.expiresAtEpochMs
            is EnrollmentUiState.WaitingTimedOut -> state.code to state.expiresAtEpochMs
            else -> null
        }
        codeText.visibility = if (code == null) View.GONE else View.VISIBLE
        expiryText.visibility = if (code == null) View.GONE else View.VISIBLE
        if (code != null) {
            codeText.text = formatEnrollmentCode(code.first)
            startCountdown(code.second)
        }

        headline.setText(headlineFor(state))
        detail.setText(detailFor(state))

        checkAgainButton.visibility = if (idle && showingCode) View.VISIBLE else View.GONE
        closeButton.setText(
            if (state is EnrollmentUiState.Enrolled) R.string.enrollment_done
            else R.string.enrollment_cancel,
        )
    }

    /** Recomputes from the wall clock every second rather than counting down from a captured value,
     *  so a screen that was backgrounded shows the truth when it comes back. */
    private fun startCountdown(expiresAtEpochMs: Long) {
        countdown = lifecycleScope.launch {
            while (true) {
                val remaining = (expiresAtEpochMs - System.currentTimeMillis()) / 1_000L
                expiryText.text = if (remaining > 0) {
                    getString(R.string.enrollment_code_expiry, remaining.toInt())
                } else {
                    getString(R.string.enrollment_code_expiry_now)
                }
                delay(1_000L)
            }
        }
    }

    private fun headlineFor(state: EnrollmentUiState): Int = when (state) {
        EnrollmentUiState.CheckingIdentity -> R.string.enrollment_checking
        EnrollmentUiState.PublishingKey -> R.string.enrollment_publishing
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_waiting
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_waiting
        EnrollmentUiState.Opening -> R.string.enrollment_opening
        EnrollmentUiState.AwaitingAuth -> R.string.enrollment_awaiting_auth
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled
        is EnrollmentUiState.Unavailable -> unavailableCopy(state.reason)
        is EnrollmentUiState.Failed -> failureCopy(state.reason)
    }

    private fun detailFor(state: EnrollmentUiState): Int = when (state) {
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_code_intro
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_timed_out
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled_detail
        else -> R.string.empty_string
    }

    private fun unavailableCopy(reason: UnavailableReason): Int = when (reason) {
        UnavailableReason.NOT_PAIRED -> R.string.enrollment_unavailable_not_paired
        UnavailableReason.HOSTILE_LOCATION -> R.string.enrollment_unavailable_hostile_location
        UnavailableReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_unavailable_no_lock_screen
        UnavailableReason.NO_IDENTITY -> R.string.enrollment_unavailable_no_identity
        UnavailableReason.SERVER_HELD_KEY -> R.string.enrollment_unavailable_server_held
        UnavailableReason.COULD_NOT_CHECK -> R.string.enrollment_unavailable_could_not_check
    }

    private fun failureCopy(reason: FailureReason): Int = when (reason) {
        // The only failure with its own copy — see the string's comment.
        FailureReason.COULD_NOT_OPEN -> R.string.enrollment_failed_could_not_open
        FailureReason.UNAUTHORIZED -> R.string.enrollment_failed_unauthorized
        FailureReason.RATE_LIMITED -> R.string.enrollment_failed_rate_limited
        FailureReason.NO_SECURE_LOCK_SCREEN -> R.string.enrollment_failed_no_lock_screen
        FailureReason.NO_DEVICE_KEY -> R.string.enrollment_failed_no_device_key
        FailureReason.PUBLISH_REJECTED -> R.string.enrollment_failed_generic
        FailureReason.ENVELOPE_MALFORMED -> R.string.enrollment_failed_generic
        FailureReason.SEAL_FAILED -> R.string.enrollment_failed_generic
    }
}
