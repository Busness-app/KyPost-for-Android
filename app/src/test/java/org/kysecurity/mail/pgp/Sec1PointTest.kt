package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

/** SEC1 P-256 encoding: a bit-for-bit contract with the Go server and the browser client. */
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

    /** `BigInteger.toByteArray()` prepends a 0x00 sign byte; it must be stripped, not carried. */
    @Test
    fun coordinateWithASignByteIsStripped() {
        val raw = ByteArray(32) { 0xFF.toByte() }
        val x = BigInteger(1, raw)
        assertEquals("precondition: toByteArray must be 33 bytes here", 33, x.toByteArray().size)

        val point = sec1UncompressedPoint(x, BigInteger.ONE)

        assertEquals(65, point.size)
        assertEquals("ff".repeat(32), point.copyOfRange(1, 33).hex())
    }

    /** The branch the instrumented test almost never reaches: roughly one random key in 128. */
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
