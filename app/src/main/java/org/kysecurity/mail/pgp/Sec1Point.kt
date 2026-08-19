package org.kysecurity.mail.pgp

import java.math.BigInteger

/** A P-256 coordinate is always encoded in exactly 32 bytes, whatever its magnitude. */
private const val COORDINATE_BYTES = 32

/** A bit-for-bit contract with the Go server and TS client — an encoding bug looks like an attack. */
internal fun sec1UncompressedPoint(x: BigInteger, y: BigInteger): ByteArray =
    byteArrayOf(0x04) + coordinate(x) + coordinate(y)

private fun coordinate(v: BigInteger): ByteArray {
    val b = v.toByteArray()
    val trimmed = if (b.size > COORDINATE_BYTES) b.copyOfRange(b.size - COORDINATE_BYTES, b.size) else b
    return ByteArray(COORDINATE_BYTES - trimmed.size) + trimmed
}
