package org.kysecurity.mail.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

private const val STORE = "encrypted_prefs_reset_test"
private const val VALUE_KEYSET = "__androidx_security_crypto_encrypted_prefs_value_keyset__"

/**
 * The device half of [org.kysecurity.mail.security.UnrecoverableKeysetTest], which can only reach
 * the parse-failure proof: everything else in [isUnrecoverableKeyset] needs a real AndroidKeyStore.
 */
@RunWith(AndroidJUnit4::class)
class EncryptedPrefsResetTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Before
    @After
    fun removeTheStore() {
        context.deleteSharedPreferences(STORE)
        acknowledgeCredentialResets(context)
    }

    private fun rawPrefs() = context.getSharedPreferences(STORE, Context.MODE_PRIVATE)

    private fun corruptTheValueKeyset(replacement: String) {
        openEncryptedPrefs(context, STORE).edit().putString("k", "v").commit()
        assertNotNull("expected a keyset to corrupt", rawPrefs().getString(VALUE_KEYSET, null))
        rawPrefs().edit().putString(VALUE_KEYSET, replacement).commit()
    }

    private fun reopenAndAssertReset() {
        var resetCause: Throwable? = null
        val reopened = openEncryptedPrefs(context, STORE) { resetCause = it }

        assertNotNull("the store must be reset, not left unopenable", resetCause)
        assertNull("a reset store must read empty", reopened.getString("k", null))

        // A shell that cannot be written to is not a recovery.
        reopened.edit().putString("k", "v2").commit()
        assertEquals("v2", openEncryptedPrefs(context, STORE).getString("k", null))
        assertEquals(setOf(STORE), credentialResetsPending(context))
    }

    /** THE CI FAILURE THIS FILE EXISTS FOR. Tink answers a keyset holding no key material with a
     *  plain `GeneralSecurityException("empty keyset")` — never a parse failure — so the only two
     *  proofs the classifier accepted left this store permanently unopenable and the app blocked
     *  at every launch. Reached here through a zero-length keyset, which is deterministic;
     *  corrupting a live one lands on this branch or the parse branch depending on the bytes. */
    @Test
    fun aKeysetHoldingNoKeyMaterialIsReset() {
        corruptTheValueKeyset("")
        reopenAndAssertReset()
    }

    /** Hex-valid rubbish: sometimes a parse failure, sometimes an empty keyset, sometimes a
     *  decrypt failure Tink cannot attribute. All three are the same fact about the store. */
    @Test
    fun aKeysetOverwrittenWithRubbishIsReset() {
        corruptTheValueKeyset("0badc0de".repeat(8))
        reopenAndAssertReset()
    }

    @Test
    fun anIntactStoreIsNeverReset() {
        var resetCause: Throwable? = null
        openEncryptedPrefs(context, STORE) { resetCause = it }.edit().putString("k", "v").commit()
        val reopened = openEncryptedPrefs(context, STORE) { resetCause = it }

        assertNull("nothing may be destroyed on a healthy store", resetCause)
        assertEquals("v", reopened.getString("k", null))
        assertEquals(emptySet<String>(), credentialResetsPending(context))
    }
}
