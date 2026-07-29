package com.urlxl.mail.security

import android.content.Context
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Re-wraps the current pairing's `deviceSecret` behind the credential key whenever it isn't
 * already wrapped under the current scheme.
 *
 * Two cases reach here:
 *
 * 1. It is stored unwrapped from before the gate was switched on — the pairing predates the toggle,
 *    so the secret sits in the clear behind a gate the user believes is closed.
 * 2. It was wrapped by a build from before the Keystore pepper existed
 *    ([com.urlxl.mail.push.SecurePairingStore.SECRET_VERSION_LEGACY]), and is therefore still
 *    brute-forceable offline. Re-wrapping migrates it to the peppered key.
 *
 * **This is a migration, not a recovery.** It can only re-wrap a secret that is still readable; a
 * secret that was never stored is gone, and the `isNullOrBlank` guard below returns rather than
 * pretending otherwise. Keeping a secret storable in the first place is
 * [com.urlxl.mail.push.PushRepository.canPersistDeviceSecret]'s job, enforced in
 * [com.urlxl.mail.push.PushSyncCoordinator] before any registration mints one.
 *
 * Call after every successful PIN unlock (see [UnlockActivity]) — at that point a fresh credential
 * key is cached and either gap can be closed immediately. A biometric unlock derives no PIN key, so
 * [UnlockActivity] demands the PIN outright whenever the gate is on rather than leaving these gaps
 * open until some later unlock that a biometric user may never perform.
 *
 * `Dispatchers.Default`, not [NonCancellable] alone. `withContext` replaces only the context
 * elements it is handed, and [NonCancellable] is a [kotlinx.coroutines.Job] — the dispatcher is
 * inherited. Every caller here is an Activity's `lifecycleScope`, i.e. `Dispatchers.Main.immediate`,
 * so the Keystore reads, the AES-GCM unwrap and the `commit()` below all ran on the UI thread.
 */
suspend fun rewrapPairingIfNeeded(context: Context, appLockManager: AppLockManager) {
    withContext(Dispatchers.Default + NonCancellable) {
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
