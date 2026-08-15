package org.kysecurity.mail.security

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyInfo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * The gate the MFA approval screen falls back to when nothing is sealed.
 *
 * The success path needs a live prompt and no automated test can produce one, so what is pinned
 * here is the property the gate rests on: without the user, the key does not work. If that ever
 * stops being true the screen is back to trusting a callback.
 */
@RunWith(AndroidJUnit4::class)
class AuthGateKeyTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private fun deviceSecure(): Boolean =
        context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    @Before fun clean() { AuthGateKey.destroy() }
    @After fun cleanup() { AuthGateKey.destroy() }

    @Test
    fun theGateKeyCannotBeUsedWithoutTheUser() {
        assumeTrue("needs a secure lock screen", deviceSecure())

        val cipher = AuthGateKey.cipher()
        assertNotNull("a secure device must be able to hold the gate key", cipher)

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(AuthGateKey.ALIAS, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        assertTrue("must require user authentication", info.isUserAuthenticationRequired)
        // What matters is that there is no time window in which one earlier unlock keeps paying for
        // later operations. The two Keystore APIs spell "authenticate for every use" differently:
        // the legacy setUserAuthenticationValidityDurationSeconds uses -1, while
        // setUserAuthenticationParameters — the only one this codebase calls, and the only one
        // available at minSdk 31 — uses 0, which is what KeyInfo then reports back. Pinning -1 here
        // pinned the sentinel of an API AuthGateKey never uses. Any POSITIVE value is the real
        // regression, so that is what this rules out.
        assertTrue(
            "a per-use key must have no validity window, got ${info.userAuthenticationValidityDurationSeconds}s",
            info.userAuthenticationValidityDurationSeconds <= 0,
        )

        // init succeeds on a user-auth key; the refusal lands at doFinal.
        assertThrows(Exception::class.java) { cipher!!.doFinal(ByteArray(16)) }
    }

    /** No secure lock screen means no key, so [AuthGateKey.cipher] hands back null and the caller
     *  fails closed rather than raising a prompt that proves nothing. */
    @Test
    fun anInsecureDeviceGetsNoKey() {
        assumeTrue("only meaningful without a lock screen", !deviceSecure())

        assertNull(AuthGateKey.cipher())
    }

    @Test
    fun destroyRemovesTheKey() {
        assumeTrue("needs a secure lock screen", deviceSecure())
        AuthGateKey.cipher()

        assertTrue(AuthGateKey.destroy().isEmpty())

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(AuthGateKey.ALIAS))
    }
}
