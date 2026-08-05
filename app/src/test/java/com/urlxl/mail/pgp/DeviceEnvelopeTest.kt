package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class DeviceEnvelopeTest {

    /** RFC 5869 Test Case 1 — an independent vector, so this confirms the HKDF agrees with the
     *  standard rather than merely round-tripping through itself. */
    @Test
    fun hkdf_matchesRfc5869TestCase1() {
        val okm = hkdfSha256(
            ikm = ByteArray(22) { 0x0b },
            salt = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
            info = byteArrayOf(
                0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(),
                0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte(),
            ),
            length = 42,
        )

        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.joinToString("") { "%02x".format(it) },
        )
    }

    /** The AAD is a three-implementation contract; its exact bytes stop an envelope minted for one
     *  device being replayed at another, and stop one surviving an identity rotation. */
    @Test
    fun aad_isTheExactContractString() {
        val aad = deviceEnrollmentAadFixture()
        assertEquals("kypost-device-envelope/v1|dev-1|ABCD1234", String(aad, Charsets.UTF_8))
    }

    @Test
    fun parse_rejectsAnUnsupportedVersion() {
        assertNull(parseDeviceEnvelope("""{"v":2,"alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":"AA==","iv":"AA==","ct":"AA=="}"""))
    }

    @Test
    fun parse_rejectsAnUnsupportedAlg() {
        assertNull(parseDeviceEnvelope("""{"v":1,"alg":"something-else","epk":"AA==","iv":"AA==","ct":"AA=="}"""))
    }

    @Test
    fun parse_rejectsGarbage() {
        assertNull(parseDeviceEnvelope("not json"))
    }

    /** Opening must succeed with the right AAD... */
    @Test
    fun open_returnsThePlaintext() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertEquals(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnrollmentAadFixture()),
        )
    }

    /** ...and fail closed with a wrong deviceId. Hostile or stale — never a retry. */
    @Test
    fun open_refusesAWrongDeviceId() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertNull(
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnvelopeAad("other-device", "ABCD1234")),
        )
    }

    /** ...and with a wrong fingerprint, which is what stops an envelope outliving a rotation. */
    @Test
    fun open_refusesAWrongFingerprint() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertNull(
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnvelopeAad("dev-1", "FFFFFFFF")),
        )
    }

    private fun deviceEnrollmentAadFixture() = deviceEnvelopeAad("dev-1", "ABCD1234")

    /** Seals with the same KDF the implementation derives, so the test exercises the real key
     *  schedule rather than a hand-picked key. */
    private fun sealedFixture(aad: ByteArray): DeviceEnvelopeFields {
        val key = hkdfSha256(FIXTURE_SECRET, FIXTURE_SALT, "kypost-device-envelope/v1".toByteArray(), 32)
        val iv = ByteArray(12) { it.toByte() }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal("-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray())
        return DeviceEnvelopeFields(epk = ByteArray(65), iv = iv, ct = ct)
    }

    private companion object {
        val FIXTURE_SECRET = ByteArray(32) { 0x11 }
        val FIXTURE_SALT = ByteArray(65) { 0x22 }
    }
}
