package com.urlxl.mail.pgp

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
 *
 * Two cases [BigInteger.toByteArray] gets wrong for this purpose, both handled here:
 *  - **33 bytes with a leading `0x00` sign byte**, whenever the coordinate's top bit is set —
 *    roughly half of all real keys. The sign byte must be stripped, not encoded.
 *  - **Fewer than 32 bytes**, for a coordinate with leading zeros. It must be left-padded, not
 *    right-aligned or emitted short. Occurs in about one random key in 128, which is why an
 *    instrumented test over generated keys effectively never exercises it.
 */
internal fun sec1UncompressedPoint(x: BigInteger, y: BigInteger): ByteArray =
    byteArrayOf(0x04) + coordinate(x) + coordinate(y)

private fun coordinate(v: BigInteger): ByteArray {
    val b = v.toByteArray()
    val trimmed = if (b.size > COORDINATE_BYTES) b.copyOfRange(b.size - COORDINATE_BYTES, b.size) else b
    return ByteArray(COORDINATE_BYTES - trimmed.size) + trimmed
}
