// androidx.security-crypto is deprecated with no replacement; swapping it is a format migration.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.GeneralSecurityException

private const val TAG = "EncryptedPrefs"

/** Plain, so it survives the reset it reports; not in [SecurityWipe]'s retained set. */
internal const val CREDENTIAL_RESET_PREFS = "org.kysecurity.mail.credential_reset"

/** The ONE AndroidKeyStore alias every encrypted store in this app is sealed under.
 *
 *  Named here rather than left implicit in [createEncryptedPrefs]'s defaulted builder, because
 *  [SecurityWipe] has to destroy it: deleting the prefs FILES without this key leaves a recovered
 *  blob decryptable, which is the same argument the credential peppers already carry. */
internal val ENCRYPTED_PREFS_MASTER_KEY_ALIAS: String = MasterKey.DEFAULT_MASTER_KEY_ALIAS

/** Resets only on a genuinely undecryptable keyset; every other failure propagates. */
internal fun openEncryptedPrefs(
    context: Context,
    fileName: String,
    onReset: (Throwable) -> Unit = {},
): SharedPreferences {
    val appContext = context.applicationContext
    return try {
        createEncryptedPrefs(appContext, fileName)
    } catch (e: GeneralSecurityException) {
        resetUnreadableStore(appContext, fileName, e, onReset)
    } catch (e: java.io.IOException) {
        // Tink reports an unreadable keyset as an IOException too, so this cannot be blanket
        // propagated — but an ordinary I/O failure must be. [isUnrecoverableKeyset] is the
        // distinction; anything else is transient and rethrows.
        if (isUnrecoverableKeyset(e)) {
            resetUnreadableStore(appContext, fileName, e, onReset)
        } else {
            Log.e(TAG, "Encrypted store '$fileName' could not be opened; NOT resetting it", e)
            throw e
        }
    }
}

/** True only when the keyset is gone or unparseable; transient storage failures are not. */
internal fun isUnrecoverableKeyset(failure: Throwable): Boolean =
    // Bounded: a cause chain does not legitimately nest this deep, and a cyclic one would hang
    // app startup, since this decides whether LockedActivity can build the security graph at all.
    generateSequence(failure) { it.cause }.take(MAX_CAUSE_DEPTH).any { cause ->
        cause is GeneralSecurityException || cause.isProtobufParseFailure()
    }

private const val MAX_CAUSE_DEPTH = 16

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
