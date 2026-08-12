package org.kysecurity.mail.pgp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The HKDF `info` string. Moves together with the version tag and the AAD prefix — changing one
 * alone strands every enrolled device.
 *
 * **v1 → v2 (2026-08-05):** the AAD stopped being pipe-delimited concatenation and became
 * length-prefixed. See [deviceEnvelopeAad].
 */
private const val ENVELOPE_INFO = "kypost-device-envelope/v2"
private const val ENVELOPE_VERSION = "2"
private const val ENVELOPE_ALG = "ECDH-P256+HKDF-SHA256+A256GCM"
private const val GCM_TAG_BITS = 128

/** HKDF-SHA256 (RFC 5869), extract-then-expand. Built from [Mac] rather than pulled in as a
 *  dependency: this app adds none for crypto. */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(salt, "HmacSHA256"))
    val prk = mac.doFinal(ikm)

    val out = ByteArray(length)
    var previous = ByteArray(0)
    var written = 0
    var counter = 1
    while (written < length) {
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(previous)
        mac.update(info)
        mac.update(counter.toByte())
        previous = mac.doFinal()
        val take = minOf(previous.size, length - written)
        previous.copyInto(out, written, 0, take)
        written += take
        counter++
    }
    return out
}

internal data class DeviceEnvelopeFields(val epk: ByteArray, val iv: ByteArray, val ct: ByteArray)

/**
 * Parses the envelope, returning null for anything malformed, unsupported, or wrong-sized. The
 * caller treats null as "re-run the ceremony", never as a retry.
 *
 * Parsed with kotlinx.serialization rather than `org.json`, deliberately. `org.json` on the unit-test
 * classpath resolves to the stubbed `android.jar`, and with `isReturnDefaultValues = true` every stub
 * method returns a default — so this function returned null for *every* input under test, including
 * well-formed envelopes, and all of its tests passed vacuously. Replacing the whole body with
 * `= null` left the suite green. This file is meant to be pure JVM; `org.json` was the one thing
 * making it not.
 */
internal fun parseDeviceEnvelope(json: String): DeviceEnvelopeFields? = runCatching {
    val o = Json.parseToJsonElement(json).jsonObject
    if (o["v"]?.jsonPrimitive?.content != ENVELOPE_VERSION) return null
    if (o["alg"]?.jsonPrimitive?.content != ENVELOPE_ALG) return null
    val decoder = Base64.getDecoder()
    val epk = decoder.decode(o.getValue("epk").jsonPrimitive.content)
    val iv = decoder.decode(o.getValue("iv").jsonPrimitive.content)
    val ct = decoder.decode(o.getValue("ct").jsonPrimitive.content)
    // Match the browser, which requires exactly 65 bytes with an 0x04 prefix before it will import
    // the point. Rejecting compressed markers, the point at infinity and trailing junk here means
    // the ECDH layer is not the only thing standing between an attacker-supplied blob and the key.
    if (epk.size != 65 || epk[0] != 0x04.toByte()) return null
    if (iv.size != 12 || ct.size <= GCM_TAG_BITS / 8) return null
    DeviceEnvelopeFields(epk = epk, iv = iv, ct = ct)
}.getOrNull()

/**
 * Binds the sealing to this device and this identity, as **length-prefixed** fields.
 *
 * `info || uint16BE(len(deviceId)) || deviceId || uint16BE(len(fingerprint)) || fingerprint`
 *
 * It used to be `info|deviceId|fingerprint` — unescaped pipe concatenation, which is ambiguous: an
 * envelope sealed under (deviceId = "dev|BADC0FFEE", fp = "0123...") produces byte-identical AAD to
 * one sealed under (deviceId = "dev", fp = "BADC0FFEE|0123..."), and each opens under the other.
 * That was not exploitable as it stood — cross-device replay already fails at the HKDF, whose salt is
 * this device's own public key, and two fixed-length hex fingerprints cannot collide across the
 * boundary — but it is a latent structural weakness, and Matrix uses a structured transcript rather
 * than a delimiter precisely because this class produced real key-binding CVEs there. Length
 * prefixing removes the class rather than arguing about reachability, and it costs two bytes a field.
 *
 * Normalises and validates [pgpFingerprint] rather than trusting the caller. The requirement used to
 * be a KDoc comment, and the repository's only fingerprint producer — [PgpFingerprint.compute], via
 * `ownFingerprintFromBootstrap` — returns *space-grouped* hex, while the browser strips whitespace
 * before building its AAD. So the natural implementation of the caller produced an AAD that could
 * never authenticate, and the design's error table turns that into "hostile or stale, no retry",
 * which the browser reports as *"the key this server gave the browser is not the key on that
 * device"*. A formatting bug arriving as a substituted-key alarm trains users to dismiss the one
 * alarm this feature has. A doc comment is not a contract across three implementations.
 */
internal fun deviceEnvelopeAad(deviceId: String, pgpFingerprint: String): ByteArray {
    val fingerprint = pgpFingerprint.uppercase().filterNot { it.isWhitespace() }
    require(fingerprint.isNotEmpty() && fingerprint.all { it in "0123456789ABCDEF" }) {
        "pgpFingerprint must be hex; got '${pgpFingerprint.take(24)}'"
    }
    val info = ENVELOPE_INFO.toByteArray(Charsets.UTF_8)
    val id = deviceId.toByteArray(Charsets.UTF_8)
    val fp = fingerprint.toByteArray(Charsets.UTF_8)
    require(id.size <= 0xFFFF && fp.size <= 0xFFFF) { "AAD field too long to length-prefix" }
    return ByteBuffer.allocate(info.size + 2 + id.size + 2 + fp.size)
        .order(ByteOrder.BIG_ENDIAN)
        .put(info)
        .putShort(id.size.toShort())
        .put(id)
        .putShort(fp.size.toShort())
        .put(fp)
        .array()
}

/**
 * Opens the envelope, or returns null if GCM authentication fails.
 *
 * A null here is **hostile or stale, never a retry**: the AAD binds the sealing to this device and
 * this identity, so a failure means the envelope was minted for someone else or under an identity
 * the account no longer advertises.
 *
 * [ownRawPublicKey] is the HKDF salt — this device's own raw 65-byte SEC1 point, not the ephemeral
 * one in the envelope.
 *
 * Returns **bytes, not a `String`**, for two reasons. A JVM `String` cannot be zeroed, and design
 * decision 3 requires the caller to hold the armored key only until the app locks and then clear
 * it — impossible for a value whose backing array is immutable and shared. And `String(bytes, UTF_8)`
 * is silently lossy: malformed bytes become U+FFFD and the function returns non-null, which reads as
 * success while handing back different bytes than were sealed. The intermediate key material is
 * zeroed here; the plaintext's lifetime belongs to the caller.
 */
internal fun openDeviceEnvelope(
    sharedSecret: ByteArray,
    ownRawPublicKey: ByteArray,
    fields: DeviceEnvelopeFields,
    aad: ByteArray,
): ByteArray? {
    var key: ByteArray? = null
    return try {
        key = hkdfSha256(sharedSecret, ownRawPublicKey, ENVELOPE_INFO.toByteArray(Charsets.UTF_8), 32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, fields.iv))
        cipher.updateAAD(aad)
        cipher.doFinal(fields.ct)
    } catch (e: Exception) {
        null
    } finally {
        // The derived key opens the account's PGP private key; do not leave it resident for GC.
        key?.fill(0)
    }
}
