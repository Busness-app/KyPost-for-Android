package com.urlxl.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class EnrollmentKeyStoreTest {

    // Block bodies, not expression bodies: deleteKeyPair now returns whether the alias is gone, and
    // JUnit rejects a @Before/@After whose method is not void.
    @Before fun clean() { EnrollmentKeyStore.deleteKeyPair() }
    @After fun cleanup() { EnrollmentKeyStore.deleteKeyPair() }

    @Test
    fun generatesAnUncompressedSec1Point() {
        assertTrue(EnrollmentKeyStore.newKeyPair())

        val raw = EnrollmentKeyStore.rawPublicKey()
        assertNotNull(raw)
        assertEquals(65, raw!!.size)
        assertEquals(0x04.toByte(), raw[0])
        assertEquals(88, EnrollmentKeyStore.encodedPublicKey()!!.length)
    }

    /** The whole design rests on this: an attacker holding the sealed envelope must not be able to
     *  obtain the key that opens it. */
    @Test
    fun thePrivateHalfCannotBeExported() {
        EnrollmentKeyStore.newKeyPair()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(EnrollmentKeyStore.ALIAS, null) as KeyStore.PrivateKeyEntry

        // A Keystore private key never yields raw material: getEncoded() returns null.
        assertEquals(null, entry.privateKey.encoded)
    }

    /**
     * The key must ROTATE, not persist. It used to be idempotent — `ensureKeyPair` returned early
     * when the alias existed — and that made it a permanent, unauthenticated Keystore key.
     *
     * Two consequences, both real. It became a standing path to every envelope the relay has ever
     * retained, openable with no prompt of any kind, which defeats [EnrollmentVault]'s per-use
     * authentication by a parallel route. And it gave an attacker unbounded lead time to precompute
     * against a stable, known public key, which is what makes grinding the enrollment code
     * affordable.
     */
    @Test
    fun newKeyPairRotatesRatherThanReusing() {
        EnrollmentKeyStore.newKeyPair()
        val first = EnrollmentKeyStore.rawPublicKey()!!.joinToString("") { "%02x".format(it) }

        EnrollmentKeyStore.newKeyPair()
        val second = EnrollmentKeyStore.rawPublicKey()!!.joinToString("") { "%02x".format(it) }

        assertNotEquals("a second ceremony must not reuse the first ceremony's key", first, second)
    }

    /** Both sides of an ECDH must land on the same secret, or nothing decrypts. */
    @Test
    fun sharedSecretAgreesWithAPeer() {
        EnrollmentKeyStore.newKeyPair()
        val peer = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val ours = EnrollmentKeyStore.sharedSecret(rawSec1(peer.public as java.security.interfaces.ECPublicKey))
        assertNotNull(ours)
        assertEquals(32, ours!!.size)
    }

    private fun rawSec1(key: java.security.interfaces.ECPublicKey): ByteArray {
        val x = key.w.affineX.toByteArray().takeLast(32).toByteArray()
        val y = key.w.affineY.toByteArray().takeLast(32).toByteArray()
        return byteArrayOf(0x04) + ByteArray(32 - x.size) + x + ByteArray(32 - y.size) + y
    }
}
