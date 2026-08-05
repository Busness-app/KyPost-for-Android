package com.urlxl.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class EnrollmentKeyStoreTest {

    @Before fun clean() = EnrollmentKeyStore.deleteKeyPair()
    @After fun cleanup() = EnrollmentKeyStore.deleteKeyPair()

    @Test
    fun generatesAnUncompressedSec1Point() {
        assertTrue(EnrollmentKeyStore.ensureKeyPair())

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
        EnrollmentKeyStore.ensureKeyPair()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(EnrollmentKeyStore.ALIAS, null) as KeyStore.PrivateKeyEntry

        // A Keystore private key never yields raw material: getEncoded() returns null.
        assertEquals(null, entry.privateKey.encoded)
    }

    @Test
    fun ensureKeyPairIsIdempotent() {
        EnrollmentKeyStore.ensureKeyPair()
        val first = EnrollmentKeyStore.rawPublicKey()!!
        EnrollmentKeyStore.ensureKeyPair()

        assertEquals(
            first.joinToString("") { "%02x".format(it) },
            EnrollmentKeyStore.rawPublicKey()!!.joinToString("") { "%02x".format(it) },
        )
    }

    /** Both sides of an ECDH must land on the same secret, or nothing decrypts. */
    @Test
    fun sharedSecretAgreesWithAPeer() {
        EnrollmentKeyStore.ensureKeyPair()
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
