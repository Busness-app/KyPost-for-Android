// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.GeneralSecurityException
import java.security.KeyStore

private const val TAG = "EncryptedPrefs"

/** Plain, so it survives the reset it reports; not in [SecurityWipe]'s retained set. */
internal const val CREDENTIAL_RESET_PREFS = "org.kysecurity.mail.credential_reset"

/** The ONE AndroidKeyStore alias every encrypted store in this app is sealed under.
 *
 *  Named here rather than left implicit in [createEncryptedPrefs]'s defaulted builder, because
 *  [SecurityWipe] has to destroy it: deleting the prefs FILES without this key leaves a recovered
 *  blob decryptable, which is the same argument the credential peppers already carry. */
internal val ENCRYPTED_PREFS_MASTER_KEY_ALIAS: String = MasterKey.DEFAULT_MASTER_KEY_ALIAS

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/** Retries before a failure is classified at all. AndroidKeyStore is routinely unavailable for a
 *  few hundred milliseconds around boot, and that window used to be enough to destroy a mailbox. */
private const val OPEN_ATTEMPTS = 3
private const val OPEN_RETRY_BACKOFF_MS = 120L

/** Opening failed and the store is NOT known to be unrecoverable, so nothing was deleted.
 *
 *  Callers must treat this as "unknown", never as "empty". [AppLockStore.tripwireBroken] answers
 *  null on it and [LockedActivity] blocks — because the alternative, which this app shipped, was
 *  reading a transient Keystore fault as a vanished PIN hash and wiping the device over it. */
class EncryptedStoreUnavailableException(fileName: String, cause: Throwable) :
    IllegalStateException("Encrypted store '$fileName' could not be opened", cause)

/**
 * Opens [fileName], resetting it ONLY when the keyset is provably undecryptable.
 *
 * "Provably" is the whole contract. Deleting an encrypted store is destruction of user data and
 * [AppLockStore.tripwireBroken] turns an empty app-lock store into a full device wipe, so the bar
 * for it is positive evidence — a keyset that will not parse, or a master key alias that is
 * confirmed absent — and never merely "an exception came out of Tink". Everything else throws
 * [EncryptedStoreUnavailableException] and the app blocks until the next launch.
 */
internal fun openEncryptedPrefs(
    context: Context,
    fileName: String,
    onReset: (Throwable) -> Unit = {},
): SharedPreferences {
    val appContext = context.applicationContext
    var last: Throwable? = null
    repeat(OPEN_ATTEMPTS) { attempt ->
        try {
            return createEncryptedPrefs(appContext, fileName)
        } catch (e: GeneralSecurityException) {
            last = e
        } catch (e: java.io.IOException) {
            // Tink reports an unreadable keyset as an IOException too, so neither exception type
            // classifies on its own; [isUnrecoverableKeyset] is the only thing that decides.
            last = e
        }
        if (attempt < OPEN_ATTEMPTS - 1) Thread.sleep(OPEN_RETRY_BACKOFF_MS)
    }

    val cause = last ?: IllegalStateException("Encrypted store '$fileName' would not open")
    if (!isUnrecoverableKeyset(cause)) {
        Log.e(TAG, "Encrypted store '$fileName' could not be opened; NOT resetting it", cause)
        throw EncryptedStoreUnavailableException(fileName, cause)
    }
    return resetUnreadableStore(appContext, fileName, cause, onReset)
}

/** True only on positive evidence that nothing can ever open this store again.
 *
 *  Two proofs are accepted, and no others. A keyset that will not parse is destroyed by
 *  definition, and a master key alias the Keystore CONFIRMS is absent can never decrypt one. A
 *  Keystore that merely refuses to answer proves nothing and is not one of them — the previous
 *  version of this function answered true for every [GeneralSecurityException], which made it a
 *  tautology over the branch that called it. */
internal fun isUnrecoverableKeyset(failure: Throwable): Boolean {
    // Bounded: a cause chain does not legitimately nest this deep, and a cyclic one would hang
    // app startup, since this decides whether LockedActivity can build the security graph at all.
    val chain = generateSequence(failure) { it.cause }.take(MAX_CAUSE_DEPTH)
    if (chain.any { it.isProtobufParseFailure() }) return true
    return masterKeyAliasPresent() == false
}

private const val MAX_CAUSE_DEPTH = 16

/** Null when the Keystore itself could not be consulted — never confused with "the alias is gone". */
private fun masterKeyAliasPresent(): Boolean? = runCatching {
    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        .containsAlias(ENCRYPTED_PREFS_MASTER_KEY_ALIAS)
}.getOrElse {
    Log.e(TAG, "Could not ask the Keystore whether the master key is still there", it)
    null
}

/** Walks the hierarchy: subclasses have their own simpleName, and the type is in shaded Tink. */
private fun Throwable.isProtobufParseFailure(): Boolean =
    generateSequence(javaClass as Class<*>?) { it.superclass }
        .any { it.simpleName == "InvalidProtocolBufferException" }

private fun resetUnreadableStore(
    appContext: Context,
    fileName: String,
    cause: Throwable,
    onReset: (Throwable) -> Unit,
): SharedPreferences {
    onReset(cause)
    Log.e(TAG, "Encrypted store '$fileName' keyset is undecryptable; resetting", cause)
    recordCredentialReset(appContext, fileName)
    appContext.deleteSharedPreferences(fileName)
    return createEncryptedPrefs(appContext, fileName)
}

internal fun recordCredentialReset(context: Context, fileName: String) {
    val prefs = context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
    val existing = prefs.getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()
    prefs.edit().putStringSet(KEY_RESET_STORES, existing + fileName).commit()
}

fun credentialResetsPending(context: Context): Set<String> =
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()

fun acknowledgeCredentialResets(context: Context) {
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .edit().remove(KEY_RESET_STORES).commit()
}

private const val KEY_RESET_STORES = "reset_stores"

private fun createEncryptedPrefs(appContext: Context, fileName: String): SharedPreferences {
    // Alias named explicitly, not left to the defaulted constructor: SecurityWipe destroys this
    // key by name, and the two must not be able to drift apart.
    val masterKey = MasterKey.Builder(appContext, ENCRYPTED_PREFS_MASTER_KEY_ALIAS)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    return EncryptedSharedPreferences.create(
        appContext,
        fileName,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
