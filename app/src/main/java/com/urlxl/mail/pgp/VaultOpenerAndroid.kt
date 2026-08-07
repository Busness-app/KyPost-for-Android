package com.urlxl.mail.pgp

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.urlxl.mail.R
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

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

    override suspend fun open(): OpenOutcome {
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
        if (!hasSecureLockScreen(activity)) return OpenOutcome.NoSecureLockScreen
        val (iv, ciphertext) = vault.stored() ?: return OpenOutcome.NotEnrolled
        // stored() non-null but openCipher() null is an invalidated/unusable key over a real blob —
        // Failed, not NotEnrolled, matching probeEnrollment's KEY_INVALIDATED case (EnrollmentState
        // .kt:31). NotEnrolled must mean "no blob was ever stored here", never "a blob exists but
        // this key can't open it" — the two need different user-facing advice (re-enrol vs. nothing
        // to do).
        val cipher = vault.openCipher(iv)
            ?: return OpenOutcome.Failed(activity.getString(R.string.email_pgp_unseal_failed))

        return suspendCancellableCoroutine { cont ->
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
                            EnrollmentSession.put(String(plaintext, Charsets.UTF_8))
                            // Zero the intermediate copy. EnrollmentSession holds a CharArray it
                            // can wipe; this ByteArray is ours to clean up.
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

            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))

            cont.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
        }
    }
}
