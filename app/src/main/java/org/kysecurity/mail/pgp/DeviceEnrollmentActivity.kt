package org.kysecurity.mail.pgp

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
import org.kysecurity.mail.R
import org.kysecurity.mail.applyGhostButtonTheme
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.security.LockedActivity
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
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
     * True once `onCreate` ran past [LockedActivity]'s gate — i.e. once [viewModel] has actually
     * been dereferenced and the sealer installed. Read by [onDestroy], which is the only method here
     * that must distinguish "this screen was never set up" from "this screen is going away".
     *
     * Deliberately **not** `redirectedToUnlock`, which `onCreate` and `onResume` use: that flag is
     * also set from `LockedActivity.onStart`, long after `onCreate` has run to completion, on the
     * ordinary "the app locked while this screen was backgrounded" exit. On that path the ViewModel
     * really does exist and a live `BiometricPrompt` really may need resolving, so keying
     * [onDestroy] off `redirectedToUnlock` would skip the seal resolution on a path that needs it —
     * leaving a `NonCancellable` continuation suspended forever with the armored private key never
     * zeroed. This flag is only ever false when `onCreate` itself bailed.
     */
    private var created = false

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

    private class LiveSeal(
        val prompt: BiometricPrompt,
        val continuation: CancellableContinuation<SealOutcome>,
    ) {
        /**
         * True once [sealExecutor] has been handed the `doFinal` + `vault.store` work — set inside
         * the same `synchronized(sealLock)` critical section that submits the task, so [onDestroy]
         * can never observe "the executor has it" and "committing is still false" as different
         * states. Only ever read or written while holding [sealLock].
         */
        var committing: Boolean = false
    }

    /**
     * The in-flight `BiometricPrompt` and the continuation waiting on it, if any.
     *
     * Exists because androidx.biometric 1.1.0 does **not** treat a configuration-change destroy the
     * way this screen needs it to: it resets its client callback to a no-op on `ON_DESTROY`
     * (`BiometricPrompt`'s internal `ResetCallbackObserver`), and on API ≥ Q it does not cancel the
     * system prompt when that destroy is a rotation — the dialog stays up and reconnects to the
     * activity-scoped `BiometricViewModel` that survives the recreation. Left alone, a user who
     * rotates while "Confirm it's you" is showing and then authenticates would see the prompt
     * dismiss with its result delivered to the now-no-op callback: the continuation this Activity
     * is holding would never be resumed, and the ceremony would hang on "Confirm it's you…"
     * forever. [onDestroy] resolves this itself instead of relying on the library — except when
     * [LiveSeal.committing] is true, in which case [sealExecutor] already owns delivering the true
     * outcome and [onDestroy] must leave the continuation alone; see [onDestroy]. `@Volatile`
     * because [resolveSeal] can run from [sealExecutor]'s thread as well as the main thread.
     */
    @Volatile
    private var liveSeal: LiveSeal? = null

    private val sealLock = Any()

    /**
     * Resolves [continuation] with [outcome] exactly once, racing safely against [onDestroy]
     * resolving the same wait from a different thread: whichever of the two clears [liveSeal]
     * first — inside the synchronized block, by continuation identity — is the one that actually
     * calls `resume`. Used only for outcomes [sealExecutor] itself produces or a failure to reach
     * it; [onDestroy]'s own cancel-on-destroy path resolves directly, because it must additionally
     * check [LiveSeal.committing] before deciding to resolve at all.
     */
    private fun resolveSeal(continuation: CancellableContinuation<SealOutcome>, outcome: SealOutcome) {
        val claimed = synchronized(sealLock) {
            if (liveSeal?.continuation === continuation) {
                liveSeal = null
                true
            } else {
                false
            }
        }
        if (claimed && continuation.isActive) continuation.resume(outcome)
    }

    /**
     * The `VaultSealer` handed to the ViewModel.
     *
     * An anonymous object rather than making this Activity implement the interface: `VaultSealer` is
     * `internal`, and a public class may not widen an internal supertype.
     */
    private val vaultSealer = object : VaultSealer {
        override suspend fun seal(plaintext: ByteArray): SealOutcome {
            val vault = EnrollmentVault(applicationContext)

            // The authority on "is there a secure lock screen", and the point where a key is
            // legitimately generated. Off the main thread: ensureKey() is a Keystore round trip
            // that, on the generate path, attempts StrongBox key generation — hundreds of
            // milliseconds to seconds — with a TEE fallback, plus the lazy
            // EncryptedSharedPreferences/Tink construction behind prefs.edit().clear().commit().
            // Nothing upstream of VaultSealer switches dispatchers, so the ceremony's coroutine
            // runs on viewModelScope's Dispatchers.Main.immediate; without this it would block the
            // UI thread for that entire round trip. The BiometricPrompt itself must stay on main,
            // so this withContext ends before that begins.
            val (ensured, cipher) = withContext(Dispatchers.IO) {
                val ok = vault.ensureKey()
                ok to if (ok) vault.sealCipher() else null
            }
            if (!ensured) {
                // ensureKey() returns false both when there is no secure lock screen AND when both
                // the StrongBox and TEE key-generation attempts fail for reasons that have nothing
                // to do with the lock screen — and sealAndReport already re-checked
                // hasSecureLockScreen() immediately before calling seal(), so by the time this
                // branch runs a lock screen is usually present. There is no SealOutcome.NoDeviceKey,
                // so this maps to the generic Failed rather than telling the user to fix something
                // that is not broken.
                return SealOutcome.Failed("The device key could not be created")
            }
            if (cipher == null) {
                return SealOutcome.Failed("The vault cipher could not be created")
            }

            return suspendCancellableCoroutine { continuation ->
                // A prompt requested after the FragmentManager has saved its state — the user hits
                // Home the instant the envelope arrives, landing here after onSaveInstanceState —
                // is silently dropped by BiometricPrompt.authenticateInternal: no exception, no
                // callback, ever. Caught here rather than left to orphan the continuation; the
                // envelope stays on the relay, so resolving as a cancel is recoverable via "Check
                // again" exactly like an ordinary dismissal.
                if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                    supportFragmentManager.isStateSaved
                ) {
                    continuation.resume(SealOutcome.Cancelled)
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
                                resolveSeal(
                                    continuation,
                                    SealOutcome.Failed("No authenticated cipher was returned"),
                                )
                                return
                            }
                            // Mark committing in the same critical section onDestroy claims
                            // liveSeal in, so the two decisions cannot interleave: either
                            // onDestroy's synchronized block already ran first and this no longer
                            // matches liveSeal (handoff below is false — nothing to commit to,
                            // the continuation is already resolved as Cancelled), or this marks
                            // first and onDestroy will then see committing == true and leave the
                            // continuation alone. Without this, onDestroy could resolve Cancelled
                            // over a write already handed to sealExecutor: the ceremony would zero
                            // the plaintext array while doFinal is still reading it, or report
                            // "cancelled" over a blob sealExecutor in fact stored — the exact lie
                            // EnrollmentVault's own KDoc says the enrollment marker must never
                            // tell, and the unsafe direction, since the user could then
                            // decommission the device that actually holds a working copy.
                            val handoff = synchronized(sealLock) {
                                val current = liveSeal
                                if (current?.continuation === continuation) {
                                    current.committing = true
                                    true
                                } else {
                                    false
                                }
                            }
                            if (!handoff) return
                            // Unreachable in practice once onDestroy has run: androidx.biometric
                            // resets this callback to a no-op on ON_DESTROY before it could ever
                            // fire again (see onDestroy and liveSeal's KDoc), and this dispatch,
                            // the handoff above, and sealExecutor.shutdown() all run on the main
                            // thread with no suspension between them, so they cannot interleave
                            // either. Kept as defence in depth. If it ever did fire post-shutdown,
                            // the right outcome is a cancel — nothing was written — not a
                            // destructive SealOutcome.Failed, which would tear down the agreement
                            // key via failAndDestroy.
                            try {
                                sealExecutor.execute {
                                    val outcome = runCatching {
                                        val ciphertext = authenticated.doFinal(plaintext)
                                        vault.store(authenticated.iv, ciphertext)
                                        SealOutcome.Sealed
                                    }.getOrElse { SealOutcome.Failed(it.message ?: "The seal failed") }
                                    resolveSeal(continuation, outcome)
                                }
                            } catch (e: RejectedExecutionException) {
                                resolveSeal(continuation, SealOutcome.Cancelled)
                            }
                        }

                        /** The user dismissing the prompt, or the library giving up on its own
                         *  (lockout, timeout). A configuration-change destroy does **not** land
                         *  here in androidx.biometric 1.1.0 — see [onDestroy], which resolves that
                         *  case itself because this callback never fires for it. */
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            resolveSeal(continuation, SealOutcome.Cancelled)
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

                // Set before authenticate(), not after: onDestroy must be able to see this the
                // moment there is a live prompt to resolve, with no window where a destroy landing
                // between authenticate() and this assignment would find nothing to cancel.
                liveSeal = LiveSeal(prompt, continuation)

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))

                // Registered after authenticate(), not before: if the continuation were already
                // cancelled on entry, an earlier registration would fire this handler immediately
                // — clearing liveSeal and calling cancelAuthentication() on a prompt not yet shown
                // — and the authenticate() call above would then leave a system dialog nothing
                // will ever dismiss.
                continuation.invokeOnCancellation {
                    synchronized(sealLock) { if (liveSeal?.continuation === continuation) liveSeal = null }
                    runCatching { prompt.cancelAuthentication() }
                }
            }
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {        setContentView(R.layout.activity_device_enrollment)
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
                // Captured so the countdown (started from inside render(), below) can be launched
                // on this same STARTED-scoped CoroutineScope rather than the wider lifecycleScope —
                // see startCountdown's KDoc.
                val scope = this
                combine(viewModel.state, viewModel.idle) { state, idle -> state to idle }
                    .collect { (state, idle) -> render(scope, state, idle) }
            }
        }

        created = true
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, checkAgainButton)
        applyGhostButtonTheme(this, closeButton)
    }

    override fun onDestroy() {
        // InboxActivity, EmailDetailActivity and ComposeActivity each note that their onDestroy
        // needs no guard, because it only touches property initializers, which exist even when
        // onCreate bailed. This one is different: it dereferences `viewModel`, and when onCreate
        // bailed at LockedActivity's gate nothing above ever has. `by viewModels()` resolves lazily,
        // so `viewModel.installSealer(null)` below would be the FIRST get on the store — and by then
        // ComponentActivity has already cleared it (on API >= 29 ON_DESTROY is dispatched from
        // dispatchActivityPreDestroyed(), before this method is even entered). ViewModelStore has no
        // "cleared" flag, so a get after clear() simply constructs a new ViewModel into a map
        // nothing will clear again: a whole DeviceEnrollmentViewModel whose init launches
        // ceremony.run(), with onCleared() — teardown()'s only caller — never running. With the
        // credential gate off (the default) that mints a P-256 agreement key and publishes its
        // public half to the relay with no screen, no user and no code ever shown, polls for five
        // minutes from a destroyed Activity, and exits at WaitingTimedOut, which by design KEEPS the
        // keypair. EnrollmentKeyStore's KDoc names exactly that outcome: the agreement key carries
        // no user-authentication requirement, justified solely by its life being one foreground
        // ceremony, so one that survives is a standing unauthenticated path to every envelope the
        // relay has retained. Reachable by backgrounding this screen, having the process reclaimed,
        // and returning past the lock grace — the restored task recreate()s for the startup
        // tripwire, and the second onCreate redirects and finishes.
        //
        // `created` and not `redirectedToUnlock` — see that property's KDoc. sealExecutor IS a
        // property initializer, so it exists here and must still be shut down or its thread leaks.
        if (!created) {
            sealExecutor.shutdown()
            super.onDestroy()
            return
        }

        // Only clear the slot if this Activity is still the one in it. On a rotation the new
        // Activity's onCreate runs BEFORE the old one's onDestroy, and isChangingConfigurations()
        // is true for exactly that case — so skipping the clear there is what stops an
        // unconditional null from uninstalling the incoming sealer and turning the next prompt
        // into a cancel. Every other path out of this screen (finish(), the app lock, the OS
        // reclaiming the process) is not a configuration change, so the clear still runs. This
        // guard is independent of the seal resolution below.
        if (!isChangingConfigurations()) {
            viewModel.installSealer(null)
        }

        // Unconditionally — including on a configuration change — resolve any seal still waiting
        // on a live BiometricPrompt, UNLESS sealExecutor already has the doFinal + store work for
        // it (LiveSeal.committing — see onAuthenticationSucceeded, which sets it in the same
        // critical section this reads it in). See liveSeal's KDoc for why androidx.biometric will
        // not resolve the non-committing case on its own across a rotation: without this, the
        // continuation this Activity is holding would never be resumed, and the screen would sit
        // on "Confirm it's you…" forever with no prompt and no way forward except Cancel (which
        // destroys the agreement key). Resolving it here instead gives back exactly what
        // onAuthenticationError already gives an ordinary dismissal: the code back on screen,
        // envelope still on the relay for seven days, recoverable via "Check again".
        //
        // The committing case must NOT resolve, and this is not just belt-and-braces: sealExecutor
        // is deliberately independent of this Activity's lifetime and its running task is not
        // interrupted by shutdown() below, so the write proceeds regardless of what happens here.
        // If this resumed Cancelled anyway, the ceremony — on Dispatchers.Main.immediate — would
        // continue INLINE inside this call: sealAndReport's Cancelled branch runs, and
        // openAndSeal's finally zeroes the same plaintext array authenticated.doFinal(plaintext)
        // may still be reading on sealExecutor's thread, while the executor either stores a valid
        // blob the ceremony believes does not exist, or stores one built from a plaintext array
        // that is being zeroed out from under it mid-read. Leaving liveSeal in place instead means
        // sealExecutor's own resolveSeal call, once doFinal + store finish, is the only thing that
        // ever resumes this continuation — with the true outcome.
        val (seal, shouldResolve) = synchronized(sealLock) {
            val current = liveSeal
            when {
                current == null -> null to false
                current.committing -> current to false
                else -> {
                    liveSeal = null
                    current to true
                }
            }
        }
        // cancelAuthentication() is called only on the path that also resolves the wait. On the
        // committing path there is no live prompt left to cancel — authentication already
        // succeeded, the fragment already delivered its result to onAuthenticationSucceeded — so
        // the call buys nothing, and leaving it in would be a second door onto the same hazard
        // this round closed: it exists purely to dismiss a dialog, but it reads as "this is still
        // this Activity's prompt to manage," which is exactly the assumption committing exists to
        // retract.
        if (seal != null && shouldResolve) {
            runCatching { seal.prompt.cancelAuthentication() }
            if (seal.continuation.isActive) {
                seal.continuation.resume(SealOutcome.Cancelled)
            }
        }

        sealExecutor.shutdown()
        super.onDestroy()
    }

    private fun render(scope: CoroutineScope, state: EnrollmentUiState, idle: Boolean) {
        countdown?.cancel()
        countdown = null

        // FLAG_KEEP_SCREEN_ON wherever the ceremony is waiting on the user with a live keypair.
        // Without it the screen times out while the user is typing into their browser, which
        // backgrounds the app, which starts the lock grace — and the user comes back to an unlock
        // prompt with the ceremony destroyed.
        //
        // ReadyToFinish is in this set even though it shows no code: it is one tap from completing,
        // and it is where a user who stepped away to fetch a fingerprint lands. Letting the screen
        // sleep there would destroy a ceremony whose envelope had already arrived. It is the same
        // set as [offersCheckAgain] minus the transient states — both answer "is the ceremony
        // waiting on a person right now".
        val awaitingTheUser = state is EnrollmentUiState.ShowingCode ||
            state is EnrollmentUiState.WaitingTimedOut ||
            state is EnrollmentUiState.ReadyToFinish

        if (awaitingTheUser) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        val code = when (state) {
            is EnrollmentUiState.ShowingCode -> state.code
            is EnrollmentUiState.WaitingTimedOut -> state.code
            else -> null
        }
        codeText.visibility = if (code == null) View.GONE else View.VISIBLE
        if (code != null) codeText.text = formatEnrollmentCode(code)

        // The countdown runs only for ShowingCode. In WaitingTimedOut the poll loop has stopped, so
        // nothing refreshes this expiry: a ticking label would count a dead bucket down past zero
        // and then sit on "about to change" forever. That state's detail line sends the user to
        // "Check again" — which reopens a window and re-derives the code — rather than to the
        // stale value beside it.
        if (state is EnrollmentUiState.ShowingCode) {
            expiryText.visibility = View.VISIBLE
            startCountdown(scope, state.expiresAtEpochMs)
        } else {
            expiryText.visibility = View.GONE
        }

        headline.setText(headlineFor(state))
        detail.setText(detailFor(state))

        checkAgainButton.visibility =
            if (offersCheckAgain(state, idle)) View.VISIBLE else View.GONE
        closeButton.setText(
            if (state is EnrollmentUiState.Enrolled) R.string.enrollment_done
            else R.string.enrollment_cancel,
        )
    }

    /**
     * Recomputes from the wall clock every second rather than counting down from a captured value,
     * so a screen that was backgrounded shows the truth when it comes back.
     *
     * Launched on [scope] — the CoroutineScope `repeatOnLifecycle(STARTED)` provides, cancelled on
     * STOP and relaunched on the next START — rather than on `lifecycleScope`, which lives until
     * DESTROYED. `lifecycleScope` would leave this ticking (and writing to [expiryText]) once a
     * second while the screen is backgrounded; render()'s own `countdown?.cancel()` cannot reach it
     * from there, because `repeatOnLifecycle`'s collector is suspended for the whole time the
     * screen is stopped, so render() itself does not run again until it resumes.
     */
    private fun startCountdown(scope: CoroutineScope, expiresAtEpochMs: Long) {
        countdown = scope.launch {
            while (true) {
                expiryText.text = when (val label = expiryCountdown(expiresAtEpochMs, System.currentTimeMillis())) {
                    is ExpiryCountdown.Counting -> resources.getQuantityString(
                        R.plurals.enrollment_code_expiry,
                        label.remainingSeconds,
                        label.remainingSeconds,
                    )
                    ExpiryCountdown.Now -> getString(R.string.enrollment_code_expiry_now)
                }
                delay(1_000L)
            }
        }
    }

    private fun headlineFor(state: EnrollmentUiState): Int = when (state) {
        EnrollmentUiState.CheckingIdentity -> R.string.enrollment_checking
        EnrollmentUiState.PublishingKey -> R.string.enrollment_publishing
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_waiting
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_waiting_timed_out
        EnrollmentUiState.Opening -> R.string.enrollment_opening
        EnrollmentUiState.AwaitingAuth -> R.string.enrollment_awaiting_auth
        EnrollmentUiState.ReadyToFinish -> R.string.enrollment_ready_to_finish
        EnrollmentUiState.Enrolled -> R.string.enrollment_enrolled
        is EnrollmentUiState.Unavailable -> unavailableCopy(state.reason)
        is EnrollmentUiState.Failed -> failureCopy(state.reason)
    }

    private fun detailFor(state: EnrollmentUiState): Int = when (state) {
        is EnrollmentUiState.ShowingCode -> R.string.enrollment_code_intro
        is EnrollmentUiState.WaitingTimedOut -> R.string.enrollment_timed_out
        EnrollmentUiState.ReadyToFinish -> R.string.enrollment_ready_to_finish_detail
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
