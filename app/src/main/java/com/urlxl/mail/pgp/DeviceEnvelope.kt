package com.urlxl.mail.pgp

import org.json.JSONObject
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The HKDF `info` string. Moves together with the `v1` tag and the AAD prefix if the format ever
 *  breaks — changing one alone strands every enrolled device. */
private const val ENVELOPE_INFO = "kypost-device-envelope/v1"
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

/** Parses the envelope, returning null for anything malformed, unsupported, or wrong-sized. The
 *  caller treats null as "re-run the ceremony", never as a retry. */
internal fun parseDeviceEnvelope(json: String): DeviceEnvelopeFields? = runCatching {
    val o = JSONObject(json)
    if (o.optInt("v") != 1) return null
    if (o.optString("alg") != ENVELOPE_ALG) return null
    val decoder = Base64.getDecoder()
    val epk = decoder.decode(o.getString("epk"))
    val iv = decoder.decode(o.getString("iv"))
    val ct = decoder.decode(o.getString("ct"))
    if (iv.size != 12 || ct.size <= GCM_TAG_BITS / 8) return null
    DeviceEnvelopeFields(epk = epk, iv = iv, ct = ct)
}.getOrNull()

/** Binds the sealing to this device and this identity. [pgpFingerprint] must be uppercase hex with
 *  no spaces. */
internal fun deviceEnvelopeAad(deviceId: String, pgpFingerprint: String): ByteArray =
    "$ENVELOPE_INFO|$deviceId|$pgpFingerprint".toByteArray(Charsets.UTF_8)

/**
 * Opens the envelope, or returns null if GCM authentication fails.
 *
 * A null here is **hostile or stale, never a retry**: the AAD binds the sealing to this device and
 * this identity, so a failure means the envelope was minted for someone else or under an identity
 * the account no longer advertises.
 *
 * [ownRawPublicKey] is the HKDF salt — this device's own raw 65-byte SEC1 point, not the ephemeral
 * one in the envelope.
 */
internal fun openDeviceEnvelope(
    sharedSecret: ByteArray,
    ownRawPublicKey: ByteArray,
    fields: DeviceEnvelopeFields,
    aad: ByteArray,
): String? = runCatching {
    val key = hkdfSha256(sharedSecret, ownRawPublicKey, ENVELOPE_INFO.toByteArray(Charsets.UTF_8), 32)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, fields.iv))
    cipher.updateAAD(aad)
    String(cipher.doFinal(fields.ct), Charsets.UTF_8)
}.getOrNull()
