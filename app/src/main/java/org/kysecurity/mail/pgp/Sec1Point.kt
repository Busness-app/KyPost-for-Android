package org.kysecurity.mail.pgp

import java.math.BigInteger

/** A P-256 coordinate is always encoded in exactly 32 bytes, whatever its magnitude. */
private const val COORDINATE_BYTES = 32

/**
 * Encodes a P-256 public key as the uncompressed SEC1 point `0x04 ‖ X ‖ Y`, each coordinate
 * left-padded to exactly 32 bytes. 65 bytes.
 *
 * Pure and Android-free so both padding branches can be unit-tested. That matters more than it
 * looks: this is a bit-for-bit contract with a Go server and a TypeScript browser client, and a
 * disagreement does not fail loudly — it fails as "the codes never match" on every honest
 * enrollment, which the browser reports to the user as *"the key this server gave the browser is
 * not the key on that device"*. An encoding bug arrives dressed as an active attack.
 */
internal fun sec1UncompressedPoint(x: BigInteger, y: BigInteger): ByteArray =
    byteArrayOf(0x04) + coordinate(x) + coordinate(y)

private fun coordinate(v: BigInteger): ByteArray {
    val b = v.toByteArray()
    val trimmed = if (b.size > COORDINATE_BYTES) b.copyOfRange(b.size - COORDINATE_BYTES, b.size) else b
    return ByteArray(COORDINATE_BYTES - trimmed.size) + trimmed
}
