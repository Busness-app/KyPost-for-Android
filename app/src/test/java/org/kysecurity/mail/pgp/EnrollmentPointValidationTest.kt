package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

/** `parseDeviceEnvelope` only checks length and prefix; this is the on-curve check. */
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
