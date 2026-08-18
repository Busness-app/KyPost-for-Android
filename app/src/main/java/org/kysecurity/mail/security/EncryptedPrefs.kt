// androidx.security-crypto is deprecated in full with no replacement API. Swapping it out is a
// migration of the at-rest credential format, not a warning fix, so it is deliberately not done
// here. File-scoped because the deprecation also fires on the imports below.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.GeneralSecurityException

private const val TAG = "EncryptedPrefs"

/** Records that an encrypted store was reset, so the app can tell the user rather than presenting
 *  a clean first-run screen over a secret it destroyed.
 *
 *  Plain, so it survives the reset of the encrypted store it is reporting on. It is deliberately
 *  **not** in [SecurityWipe]'s retained set — a full wipe destroys it along with everything else,
 *  because after a wipe there is no unexpected loss left to warn about and the notice would land on
 *  top of "your data has been erased" saying the same thing less clearly. (An earlier version of
 *  this comment claimed the opposite and was simply wrong; `PREFS_NAMES_RETAINED` never listed it.) */
internal const val CREDENTIAL_RESET_PREFS = "org.kysecurity.mail.credential_reset"

/**
 * Opens a Keystore-backed [EncryptedSharedPreferences] file, resetting it **only** when the keyset
 * is genuinely undecryptable.
 *
 * `catch (Exception)` covers far more than the key invalidation the comments named. An
 * `IOException` from a full or momentarily unavailable data partition — which is routine, and which
 * happens during direct-boot to user-unlock transitions on several OEM builds — took the same
 * branch. The user's private key was deleted because the disk was full for a second.
 *
 * So: [GeneralSecurityException] (and Tink's `KeyStoreException` wrapper for it) means the keyset
 * cannot be decrypted and the file is genuinely unreadable forever — reset, and record that we did.
 * **Everything else propagates.** A transient failure must surface as a transient failure, not as
 * silent, permanent destruction of a credential.
 *
 * @param onReset invoked before the delete, with the failure, so the caller can log in its own
 *   voice. The durable marker is written here regardless.
 */
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

/**
 * Whether [failure] means the keyset itself is gone or unparseable, as opposed to the storage
 * being briefly unavailable.
 *
 * Two shapes count:
 *
 * - a [GeneralSecurityException] anywhere in the cause chain: the master key can no longer decrypt
 *   the keyset (OS-level key invalidation, a restored backup);
 * - Tink's `InvalidProtocolBufferException`: the keyset bytes are not a valid protobuf at all, i.e.
 *   truncated or overwritten. It is itself an `IOException`, which is exactly why "IOException
 *   means transient" was too coarse. A store the app can never read again must reset, or the app
 *   cannot start at all.
 *
 * Everything else — a full disk, storage not yet mounted — rethrows, because destroying a
 * credential the user cannot get back is not an acceptable response to a transient failure.
 */
internal fun isUnrecoverableKeyset(failure: Throwable): Boolean =
    // Bounded: a cause chain does not legitimately nest this deep, and a cyclic one would hang
    // app startup, since this decides whether LockedActivity can build the security graph at all.
    generateSequence(failure) { it.cause }.take(MAX_CAUSE_DEPTH).any { cause ->
        cause is GeneralSecurityException || cause.isProtobufParseFailure()
    }

private const val MAX_CAUSE_DEPTH = 16

/**
 * Whether this throwable is a protobuf parse failure, **including the subclasses**.
 *
 * `InvalidProtocolBufferException` has nested subclasses — `InvalidWireTypeException`,
 * `TruncatedMessageException`, `SizeLimitExceededException` — and a nested class's `simpleName` is
 * its own, not its parent's. So matching `javaClass.simpleName` directly recognised only the base
 * type, and every subclass fell through to "transient, rethrow".
 *
 * That was not cosmetic. Corrupting a keyset in a way that trips `InvalidWireTypeException` (which
 * is what happens on API 31, where the stored keyset's bytes differ from API 34's) left the store
 * permanently unreadable and never reset — so `AppLockStore.isLockEnabled()` threw, out of
 * `SecurityGraph`'s constructor, out of `LockedActivity.onCreate`, and the app could not start.
 * `AppLockStoreTest.corruptedKeyset_doesNotCrash_andTripsTheTripwire` asserts the recovery; it
 * passed on API 34 and failed on 31 for this reason, taking seventeen other suites down with it
 * because the corrupted store persisted across the whole instrumentation run.
 *
 * Walking the hierarchy rather than importing the type, because it lives in Tink's *shaded*
 * protobuf package — an implementation detail this file must not depend on by name.
 */
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

/** The stores reset since the last time a screen acknowledged it, newest write wins. */
internal fun recordCredentialReset(context: Context, fileName: String) {
    val prefs = context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
    val existing = prefs.getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()
    prefs.edit().putStringSet(KEY_RESET_STORES, existing + fileName).commit()
}

/** Which encrypted stores were reset out from under the user, for a screen to report. Empty when
 *  nothing was lost. */
fun credentialResetsPending(context: Context): Set<String> =
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .getStringSet(KEY_RESET_STORES, emptySet()).orEmpty()

/** Called once the user has been told. */
fun acknowledgeCredentialResets(context: Context) {
    context.applicationContext
        .getSharedPreferences(CREDENTIAL_RESET_PREFS, Context.MODE_PRIVATE)
        .edit().remove(KEY_RESET_STORES).commit()
}

private const val KEY_RESET_STORES = "reset_stores"

private fun createEncryptedPrefs(appContext: Context, fileName: String): SharedPreferences {
    val masterKey = MasterKey.Builder(appContext)
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
