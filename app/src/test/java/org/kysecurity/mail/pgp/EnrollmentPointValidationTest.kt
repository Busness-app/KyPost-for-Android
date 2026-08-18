package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

/**
 * The on-curve check that stands between an attacker-supplied ephemeral public key and this
 * device's enrollment private key.
 *
 * `parseDeviceEnvelope` checks the blob is 65 bytes starting `0x04`. That is a length-and-prefix
 * check: it says nothing about whether (x, y) satisfies the curve equation, which is the
 * precondition for an invalid-curve attack. Before this validator the only thing rejecting such a
 * point was whichever `KeyFactory` provider happened to resolve at runtime — a property this
 * codebase asserts nowhere and does not control.
 *
 * Pure math on `java.security.spec` types, so it runs on the JVM rather than needing a device.
 */
class EnrollmentPointValidationTest {

    private val p256: ECParameterSpec = AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1"))
        getParameterSpec(ECParameterSpec::class.java)
    }

    private val prime: BigInteger =
        (p256.curve.field as java.security.spec.ECFieldFp).p

    @Test
    fun theGeneratorIsOnTheCurve() {
        assertTrue(EnrollmentKeyStore.isOnCurve(p256.generator, p256))
    }

    @Test
    fun aPointWithATamperedYIsRejected() {
        val g = p256.generator
        val offCurve = ECPoint(g.affineX, g.affineY.add(BigInteger.ONE).mod(prime))
        assertFalse(EnrollmentKeyStore.isOnCurve(offCurve, p256))
    }

    @Test
    fun aPointWithATamperedXIsRejected() {
        val g = p256.generator
        val offCurve = ECPoint(g.affineX.add(BigInteger.ONE).mod(prime), g.affineY)
        assertFalse(EnrollmentKeyStore.isOnCurve(offCurve, p256))
    }

    /** The classic invalid-curve input: small, tidy coordinates that satisfy no P-256 relation. */
    @Test
    fun aSmallOrderLookingPointIsRejected() {
        assertFalse(
            EnrollmentKeyStore.isOnCurve(ECPoint(BigInteger.ONE, BigInteger.ONE), p256),
        )
        assertFalse(
            EnrollmentKeyStore.isOnCurve(ECPoint(BigInteger.ZERO, BigInteger.ZERO), p256),
        )
    }

    /** Coordinates outside the field are rejected before any modular arithmetic can normalise
     *  them into looking valid. */
    @Test
    fun coordinatesOutsideTheFieldAreRejected() {
        val g = p256.generator
        assertFalse(EnrollmentKeyStore.isOnCurve(ECPoint(g.affineX.add(prime), g.affineY), p256))
        assertFalse(EnrollmentKeyStore.isOnCurve(ECPoint(g.affineX, g.affineY.add(prime)), p256))
        assertFalse(EnrollmentKeyStore.isOnCurve(ECPoint(BigInteger.valueOf(-1), g.affineY), p256))
    }
}
