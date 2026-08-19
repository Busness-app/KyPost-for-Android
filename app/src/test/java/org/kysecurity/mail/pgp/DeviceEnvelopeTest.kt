package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test
import kotlin.test.assertFailsWith
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
    fun aad_isTheExactContractBytes() {
        val aad = deviceEnrollmentAadFixture()

        val expected = "kypost-device-envelope/v2".toByteArray() +
            byteArrayOf(0, 5) + "dev-1".toByteArray() +
            byteArrayOf(0, 8) + "ABCD1234".toByteArray()
        assertArrayEquals(expected, aad)
    }

    /** Why the fields are length-prefixed: `info|deviceId|fingerprint` lets a boundary shift collide. */
    @Test
    fun aad_isUnambiguousAcrossAFieldBoundary() {
        val shifted = deviceEnvelopeAad("dev", "BADC0FFEE0123456789ABCDEF")
        val plain = deviceEnvelopeAad("devBADC0FFEE", "0123456789ABCDEF")

        assertFalse(
            "field boundaries must not be shiftable between deviceId and fingerprint",
            shifted.contentEquals(plain),
        )
    }

    @Test
    fun parse_acceptsAWellFormedEnvelope() {
        val fields = parseDeviceEnvelope(envelopeJson())

        assertNotNull(fields)
        assertEquals(65, fields!!.epk.size)
        assertEquals(12, fields.iv.size)
        assertEquals(32, fields.ct.size)
    }

    @Test
    fun parse_rejectsTheSupersededV1Envelope() {
        assertNull(parseDeviceEnvelope(envelopeJson(v = "1")))
    }

    @Test
    fun parse_rejectsAnUnsupportedAlg() {
        assertNull(parseDeviceEnvelope(envelopeJson(alg = "something-else")))
    }

    @Test
    fun parse_rejectsGarbage() {
        assertNull(parseDeviceEnvelope("not json"))
    }

    /** A non-96-bit IV does not throw — GCMParameterSpec accepts any length and derives J0 by GHASH
     *  — so it silently changes the key schedule and desynchronises this client from the browser.
     *  This check is the only thing that catches it. */
    @Test
    fun parse_rejectsAWrongLengthIv() {
        assertNull(parseDeviceEnvelope(envelopeJson(iv = b64(ByteArray(8)))))
    }

    @Test
    fun parse_rejectsACiphertextShorterThanTheGcmTag() {
        assertNull(parseDeviceEnvelope(envelopeJson(ct = b64(ByteArray(16)))))
    }

    /** Matches the browser, which requires exactly 65 bytes with an 0x04 prefix. Without this the
     *  ECDH layer is the only thing between an attacker-supplied blob and the enrollment key. */
    @Test
    fun parse_rejectsAnEpkThatIsNotAnUncompressedPoint() {
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(65).also { it[0] = 0x02 }))))
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(64).also { it[0] = 0x04 }))))
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(200).also { it[0] = 0x04 }))))
    }

    /** [PgpFingerprint.compute] returns space-grouped hex; the browser strips whitespace for its AAD. */
    @Test
    fun aad_normalisesASpaceGroupedFingerprint() {
        assertArrayEquals(
            deviceEnvelopeAad("dev-1", "164D5B834E7FE9272DC7293B6D78ABF3D9179534"),
            deviceEnvelopeAad("dev-1", "164D 5B83 4E7F E927 2DC7 293B 6D78 ABF3 D917 9534"),
        )
    }

    @Test
    fun aad_lowercaseHexIsNormalisedToUppercase() {
        assertArrayEquals(
            deviceEnvelopeAad("dev-1", "ABCD1234"),
            deviceEnvelopeAad("dev-1", "abcd1234"),
        )
    }

    /** Fails loudly at the call site rather than silently producing an AAD that will never open. */
    @Test(expected = IllegalArgumentException::class)
    fun aad_rejectsANonHexFingerprint() {
        deviceEnvelopeAad("dev-1", "not-a-fingerprint")
    }

    private fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

    private fun envelopeJson(
        v: String = "2",
        alg: String = "ECDH-P256+HKDF-SHA256+A256GCM",
        epk: String = b64(ByteArray(65).also { it[0] = 0x04 }),
        iv: String = b64(ByteArray(12)),
        ct: String = b64(ByteArray(32)),
    ): String = """{"v":$v,"alg":"$alg","epk":"$epk","iv":"$iv","ct":"$ct"}"""

    /** Opening must succeed with the right AAD... */
    @Test
    fun open_returnsThePlaintext() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertArrayEquals(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray(),
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
        val key = hkdfSha256(FIXTURE_SECRET, FIXTURE_SALT, "kypost-device-envelope/v2".toByteArray(), 32)
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

    /** RFC 5869's ceiling, and the reason it is enforced rather than assumed: the block counter is
     *  written as ONE byte, so at 256 blocks it wraps to zero and that round reproduces round 1's
     *  output. A silent key collision is not a failure mode worth leaving to "nobody calls it with
     *  that length". */
    @Test
    fun hkdfRefusesLengthsPastTheOneByteCounter() {
        assertFailsWith<IllegalArgumentException> {
            hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32 + 1)
        }
        assertFailsWith<IllegalArgumentException> {
            hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 0)
        }
    }

    @Test
    fun hkdfStillExpandsUpToTheCeiling() {
        assertEquals(255 * 32, hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32).size)
    }
}
