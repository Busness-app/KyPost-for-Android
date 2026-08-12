package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

/**
 * Covers the SEC1 encoding of a P-256 public key — a bit-for-bit contract shared with a Go server
 * and a TypeScript browser client. A deviation does not fail loudly: it fails as "the codes never
 * match" on every honest enrollment, which the browser reports to the user as an active attack.
 *
 * These live as JVM tests on purpose. The instrumented test can only assert the overall length of a
 * *randomly generated* key, and the interesting branch — a coordinate whose big-endian form is
 * shorter than 32 bytes, so it must be left-padded rather than truncated — occurs in roughly one
 * random key in 128. It was effectively never covered.
 */
class Sec1PointTest {

    @Test
    fun bothCoordinatesExactly32Bytes() {
        val x = BigInteger(1, ByteArray(32) { 0x11 })
        val y = BigInteger(1, ByteArray(32) { 0x22 })

        val point = sec1UncompressedPoint(x, y)

        assertEquals(65, point.size)
        assertEquals(0x04.toByte(), point[0])
        assertEquals("11".repeat(32), point.copyOfRange(1, 33).hex())
        assertEquals("22".repeat(32), point.copyOfRange(33, 65).hex())
    }

    /**
     * A coordinate whose top bit is set: `BigInteger.toByteArray()` prepends a 0x00 sign byte and
     * returns 33 bytes. The sign byte must be stripped, not carried into the encoding. Happens for
     * roughly half of all real keys.
     */
    @Test
    fun coordinateWithASignByteIsStripped() {
        val raw = ByteArray(32) { 0xFF.toByte() }
        val x = BigInteger(1, raw)
        assertEquals("precondition: toByteArray must be 33 bytes here", 33, x.toByteArray().size)

        val point = sec1UncompressedPoint(x, BigInteger.ONE)

        assertEquals(65, point.size)
        assertEquals("ff".repeat(32), point.copyOfRange(1, 33).hex())
    }

    /**
     * The branch the instrumented test almost never reaches: a small coordinate must be LEFT-padded
     * with zeros to 32 bytes. Getting this wrong right-aligns the value or shortens the point, and
     * every code derived from it disagrees with the browser's.
     */
    @Test
    fun shortCoordinateIsLeftPaddedNotTruncated() {
        val point = sec1UncompressedPoint(BigInteger.ONE, BigInteger.valueOf(0x0203))

        assertEquals(65, point.size)
        assertEquals("00".repeat(31) + "01", point.copyOfRange(1, 33).hex())
        assertEquals("00".repeat(30) + "0203", point.copyOfRange(33, 65).hex())
    }

    /** Zero is the degenerate case of the padding branch — 32 zero bytes, not an empty array. */
    @Test
    fun zeroCoordinateIsThirtyTwoZeroBytes() {
        val point = sec1UncompressedPoint(BigInteger.ZERO, BigInteger.ZERO)

        assertEquals(65, point.size)
        assertEquals("00".repeat(32), point.copyOfRange(1, 33).hex())
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
