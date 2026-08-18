package org.kysecurity.mail.pgp

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import org.kysecurity.mail.R
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * Opens the device envelope through a `BiometricPrompt.CryptoObject`, so the Keystore key's
 * `setUserAuthenticationRequired(true)` is satisfied by the same authentication the user just
 * performed.
 *
 * **This is [EnrollmentSession]'s first writer.** Decision 6 of the enrollment ceremony left the
 * holder without one on purpose: filling a process-scoped holder with the account's private key for
 * zero readers is exposure bought for nothing. The reader now exists.
 *
 * The plaintext is written into the holder here rather than returned, so it never passes back
 * through whatever orchestrator calls [open].
 */
internal class AndroidVaultOpener(private val activity: FragmentActivity) : VaultOpener {

    /**
     * The handoff between the two `withContext` blocks in [open].
     *
     * `withContext` is a regular suspend function, not `inline` — a bare `return` from inside its
     * lambda cannot leave [open] the way it could from an `inline` block, so the three early exits
     * on the IO side ([OpenOutcome.NoSecureLockScreen], [OpenOutcome.NotEnrolled], the `Failed` from
     * an unopenable cipher) have to travel out as a value instead. [Ready] carries what the Main
     * side needs next; [Blocked] carries the outcome straight through.
     */
    private sealed class VaultUnlock {
        /** Not a `data class`: `ciphertext` would be compared by identity behind a structural-looking
         *  `equals`. Nothing compares these. */
        class Ready(val cipher: Cipher, val ciphertext: ByteArray) : VaultUnlock()
        data class Blocked(val outcome: OpenOutcome) : VaultUnlock()
    }

    override suspend fun open(): OpenOutcome {
        // Everything down to openCipher() is disk and Keystore work, never Main. buildPrefs() is a
        // MasterKey Keystore round trip plus an EncryptedSharedPreferences.create — a Tink keyset
        // disk read and a Keystore unwrap — against the `device_envelope_secure` file. That is a
        // different file from the pairing store, so no earlier IO hop in the app has warmed it: the
        // first call per process pays this cold path in full. openCipher(iv) adds
        // `KeyStore.load(null)`, `getKey` and a `Cipher.init` on a user-auth-required, StrongBox-
        // preferred key — tens to hundreds of milliseconds on real hardware. This is the same
        // workload `AndroidEnrollmentTransport.pairing()`'s KDoc describes for the pairing store:
        // "Blocking, and never to be called from the main thread."
        //
        // Only the suspendCancellableCoroutine block below needs Main, because BiometricPrompt
        // .authenticate performs a FragmentManager transaction. The hop to Main has to be explicit
        // here rather than inherited from the caller: EmailDetailActivity.encryptedReader(), the one
        // caller today, builds this port from inside its own withContext(Dispatchers.IO), so without
        // this the prompt would be requested from IO, not Main.
        val unlock = withContext(Dispatchers.IO) {
            val vault = EnrollmentVault(activity)

            // hasSecureLockScreen(), not vault.ensureKey() — deliberately, not an oversight. ensureKey()
            // mutates: on a key that no longer inspects as matching spec, including a key that simply
            // fails to inspect, EnrollmentVault.existingKeyMatchesSpec() treats that as a mismatch and
            // ensureKey() falls through to generate(), which opens with prefs.edit().clear().commit() —
            // wiping the stored ciphertext before minting the new key. That mutation is only safe at the
            // seal, where a fresh key is about to be used regardless of what generate() just cleared.
            // Calling ensureKey() here, on the read path, would let a transient Keystore inspection
            // failure silently destroy a still-good envelope and report NotEnrolled over what should
            // have been Failed — this is the exact hazard hasSecureLockScreen's own KDoc names, almost
            // verbatim, at EnrollmentPortsAndroid.kt:140-145 ("Using it as a read-only probe would mean
            // opening the ceremony screen could destroy an existing enrollment. The vault still has the
            // final word at the seal, where a mutation is expected."). probeEnrollment
            // (EnrollmentState.kt:22-38) is the same non-mutating pattern used here: stored() and
            // openCipher(), never ensureKey(). Do not "simplify" this back to ensureKey() without
            // re-reading that KDoc.
            if (!hasSecureLockScreen(activity)) {
                return@withContext VaultUnlock.Blocked(OpenOutcome.NoSecureLockScreen)
            }
            val (iv, ciphertext) = vault.stored()
                ?: return@withContext VaultUnlock.Blocked(OpenOutcome.NotEnrolled)
            // stored() non-null but openCipher() null is an invalidated/unusable key over a real blob —
            // Failed, not NotEnrolled, matching probeEnrollment's KEY_INVALIDATED case (EnrollmentState
            // .kt:31). NotEnrolled must mean "no blob was ever stored here", never "a blob exists but
            // this key can't open it" — the two need different user-facing advice (re-enrol vs. nothing
            // to do).
            val cipher = vault.openCipher(iv)
                ?: return@withContext VaultUnlock.Blocked(
                    OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed)),
                )
            VaultUnlock.Ready(cipher, ciphertext)
        }
        val (cipher, ciphertext) = when (unlock) {
            is VaultUnlock.Blocked -> return unlock.outcome
            is VaultUnlock.Ready -> unlock.cipher to unlock.ciphertext
        }

        return withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                // A prompt requested after the FragmentManager has saved its state — the user
                // backgrounds the app the instant the reader starts unsealing, landing here after
                // onSaveInstanceState — is silently dropped by BiometricPrompt.authenticateInternal:
                // no exception, no callback, ever. Without this guard the continuation above would
                // never resume and open() would hang forever behind a spinner with no prompt and no
                // error. Mirrors DeviceEnrollmentActivity.vaultSealer.seal()'s identical guard, in the
                // same place — first thing inside the coroutine, before the prompt is built — and
                // Cancelled for the same reason every other BiometricPrompt outcome that isn't a real
                // unseal failure resolves to Cancelled: nothing is broken, the user can try again.
                //
                // This guard has to stay inside the coroutine, on Main, evaluated as late as
                // possible before authenticate() — not hoisted above the IO hop, and not evaluated
                // once before the withContext(Main) switch. It has to run on the thread that is
                // about to call authenticate(), right before that call, or the race it closes reopens:
                // a save-state transition between the check and the call would still get silently
                // dropped.
                if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                    activity.supportFragmentManager.isStateSaved
                ) {
                    cont.resume(OpenOutcome.Cancelled)
                    return@suspendCancellableCoroutine
                }

                val prompt = BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            val authenticated = result.cryptoObject?.cipher
                            if (authenticated == null) {
                                cont.resume(
                                    OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed)),
                                )
                                return
                            }
                            val outcome = runCatching {
                                // A GCM tag failure on doFinal means this ciphertext does not belong
                                // to this key — that is a real Failed, not a crash, and not something
                                // a retry fixes: the caller is told to re-enrol.
                                val plaintext = authenticated.doFinal(ciphertext)
                                // putUtf8, not put(String(...)): a String copy of the private key
                                // cannot be zeroed. Decoding straight into the holder's CharArray
                                // leaves nothing behind that the holder cannot wipe.
                                EnrollmentSession.putUtf8(plaintext)
                                plaintext.fill(0)
                                OpenOutcome.Opened
                            }.getOrElse {
                                OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed))
                            }
                            cont.resume(outcome)
                        }

                        /** The user dismissing the prompt, or the library giving up on its own
                         *  (lockout, timeout). Every case maps to [OpenOutcome.Cancelled], never
                         *  [OpenOutcome.Failed]: none of them says the envelope itself is broken, only
                         *  that this attempt did not go through. Mirrors
                         *  `DeviceEnrollmentActivity`'s `vaultSealer.seal()`, whose own
                         *  `onAuthenticationError` resolves the same way for the same reason. */
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            cont.resume(OpenOutcome.Cancelled)
                        }

                        // onAuthenticationFailed is a non-matching finger. The prompt stays up and the
                        // user tries again; there is nothing to resume.
                    },
                )

                // DEVICE_CREDENTIAL is allowed because the vault key itself allows it: EnrollmentVault
                // .generate() calls setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or
                // AUTH_DEVICE_CREDENTIAL), and a PromptInfo narrower than that fails at authenticate().
                // Matches DeviceEnrollmentActivity.vaultSealer.seal()'s own PromptInfo exactly. With
                // DEVICE_CREDENTIAL in the set, setNegativeButtonText must NOT be called —
                // BiometricPrompt throws if both are given.
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(activity.getString(R.string.email_pgp_unlock_title))
                    .setSubtitle(activity.getString(R.string.email_pgp_unlock_subtitle))
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()

                // The Cipher above was constructed on IO, a moment ago; a Keystore-backed Cipher
                // carries no thread affinity, so handing it to a CryptoObject built and consumed on
                // Main is safe in principle. Flagged as device-verify in the task-16 report rather
                // than asserted outright — this is the kind of boundary that stays fine until a
                // future AndroidKeyStore provider quietly makes it not.
                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))

                cont.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
            }
        }
    }
}
