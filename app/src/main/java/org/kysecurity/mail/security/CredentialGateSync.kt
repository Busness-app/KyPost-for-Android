package org.kysecurity.mail.security

import android.content.Context
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Re-wraps the pairing secret under the current credential key; call after each PIN unlock. */
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
