package com.urlxl.mail.security

import android.content.Context
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Re-wraps the current pairing's `deviceSecret` behind the credential key whenever it isn't
 * already wrapped under the current scheme.
 *
 * Two cases reach here:
 *
 * 1. It was saved unwrapped despite the gate being on. `PushRepository.savePairing` falls back to
 *    a plaintext save when the gate is on but no credential key is cached — which happens on any
 *    background FCM token rotation in a process that was never PIN-unlocked (Android routinely
 *    restarts the app to deliver FCM callbacks). The rotated secret would otherwise sit unwrapped
 *    indefinitely, silently defeating the gate.
 * 2. It was wrapped by a build from before the Keystore pepper existed
 *    ([com.urlxl.mail.push.SecurePairingStore.SECRET_VERSION_LEGACY]), and is therefore still
 *    brute-forceable offline. Re-wrapping migrates it to the peppered key.
 *
 * Call after every successful PIN unlock (see [UnlockActivity]) — at that point a fresh credential
 * key is cached and either gap can be closed immediately.
 */
suspend fun rewrapPairingIfNeeded(context: Context, appLockManager: AppLockManager) {
    withContext(NonCancellable) {
        val appLockStore = SecurityRuntime.graph(context).appLockStore
        if (!appLockStore.isCredentialPinGateEnabled()) return@withContext

        val securePairingStore = PushRuntime.graph(context).securePairingStore
        if (!securePairingStore.needsCredentialRewrap()) return@withContext

        val credentialKeys = appLockManager.cachedCredentialKeys() ?: return@withContext
        val credentialSalt = appLockStore.credentialSalt() ?: return@withContext

        // Read with the keys so a legacy-wrapped secret is decrypted before being re-wrapped; a
        // currently-unwrapped one comes back the same either way.
        val currentPairing = securePairingStore.pairingSnapshot(credentialKeys) ?: return@withContext
        if (currentPairing.deviceSecret.isNullOrBlank()) return@withContext
        securePairingStore.savePairing(currentPairing, credentialKeys, credentialSalt)
    }
}
