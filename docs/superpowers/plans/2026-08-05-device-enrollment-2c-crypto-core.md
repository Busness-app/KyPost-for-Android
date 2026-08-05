# Device Enrollment 2c — Android Crypto Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the device half of enrollment on Android — the keystore keys, opening and re-sealing the envelope, both teardown paths, and enrollment-state reporting — with no UI.

**Architecture:** One pure-JVM crypto unit (`DeviceEnvelope`) that unit-tests without a device, three Keystore-backed units behind it, three HTTP clients following the existing `MfaResponseClient` shape, and two integration points in code that already exists (`SecuritySettingsActivity.applyHostileLocationProtection`, `SecurityWipe.wipeAndResetApp`).

**Tech Stack:** Kotlin, Android Keystore (`PURPOSE_AGREE_KEY`, AES-GCM), `BiometricPrompt` with `CryptoObject`, OkHttp via the existing pinned `Call.Factory`, kotlinx.serialization, WorkManager, JUnit4 + Robolectric-free JVM tests, `androidTest` instrumented tests.

**Spec:** `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md`
**Handoff:** `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`
**Companion plan:** `2026-08-05-device-enrollment-2c-server-enrollment-state.md` — Task 5 here cannot be integration-tested until that route exists, but it can be written and unit-tested now.

## Global Constraints

- Working directory: `/home/yoshi/git/kypost-android`. Branch: `feat/device-enrollment-2c`.
- **No workaround flags are needed.** The dependency-verification gap that used to require `--no-configuration-cache` was closed properly: ten BOM/parent metadata artifacts were verified against Maven Central's published SHA-1 and recorded in `gradle/verification-metadata.xml`. The configuration cache works. Do not add entries to that file without verifying the artifact — it is a supply-chain control.
- **Ten instrumented tests fail on this emulator for a pre-existing reason**, confirmed at baseline `cdd7dbd`: `PepperUnavailableException` from `CredentialCipher`'s HMAC pepper key on Android 17. Unrelated to 2c. Do not "fix" it as part of this plan, and do not treat it as a regression you caused.
- **Add no new dependencies.** HKDF is built from `javax.crypto.Mac`; there is no third-party crypto library in this app and this work does not introduce one.
- `minSdk = 31` (`app/build.gradle.kts:27`), so `PURPOSE_AGREE_KEY` is available on every supported device.
- **Never derive the enrollment code from a server-supplied value.** It comes from the keystore key only. This is the whole control.
- **`deviceId` is hashed as-is and never normalised.** The server bounds it to `A-Z a-z 0-9 . _ : -`, all byte-identical under UTF-8, NFC and NFD.
- Device credential headers come from `Request.Builder.pairingAuthHeaders(deviceId, deviceSecret)` in `app/src/main/java/com/urlxl/mail/PairingAuthHeaders.kt` — note the path, it is **not** under `push/`.
- All HTTP clients take an injectable `Call.Factory` defaulting to the pinned one, exactly as `push/MfaResponseClient.kt` does.
- **Treat "there is a test for it" as unproven** until the implementation has been broken and the test watched going red. Two of 2b's security tests originally passed against gutted implementations — `1c74842` and `00feae6` in kypost-server.
- Wire format is settled and is a three-implementation bit-for-bit contract. Changing any of it is a break, not a fix.

## Wire format reference (do not renegotiate)

```
public key   base64(standard, padded) of 0x04 ‖ X(32) ‖ Y(32)   — 65 raw, 88 encoded
code         first 50 bits of SHA-256(rawKey(65) ‖ uint16BE(len(idUtf8)) ‖ idUtf8 ‖ uint64BE(bucket))
             as 10 Crockford base32 chars, alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ
bucket       floor(unixSeconds / 120)
envelope     {"v":1,"alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":…,"iv":…,"ct":…}  all base64
KDF          HKDF-SHA256, ikm = ECDH shared secret, salt = own raw 65-byte public key,
             info = UTF-8 "kypost-device-envelope/v1", length 32
AAD          UTF-8 "kypost-device-envelope/v1|<deviceId>|<pgpFingerprint>"   fingerprint uppercase hex, no spaces
plaintext    the armored PGP private key, UTF-8
```

## File Structure

| File | Responsibility |
|---|---|
| `pgp/DeviceEnrollmentCode.kt` | **Done** — `e0f23a8`. Code derivation. |
| `pgp/DeviceEnvelope.kt` | **New.** Pure JVM: HKDF-SHA256, envelope parse/validate, AES-256-GCM open with AAD. No Android imports, so it unit-tests on the JVM. |
| `pgp/EnrollmentKeyStore.kt` | **New.** The P-256 `PURPOSE_AGREE_KEY` pair; raw SEC1 encoding; ECDH. |
| `pgp/EnrollmentVault.kt` | **New.** The re-seal AES-GCM Keystore key and the sealed blob in its own `EncryptedSharedPreferences` file. |
| `pgp/EnrollmentState.kt` | **New.** The `Cipher.init` probe → `EnrollmentStatus`. |
| `pgp/EnrollmentClients.kt` | **New.** Three device-authed clients: publish key, fetch envelope, report state. |
| `pgp/EnrollmentStateWorker.kt` | **New.** WorkManager one-shot for the durable teardown report. |
| `pgp/EnrollmentTeardown.kt` | **New.** Destroys both keys and the blob. One function, two callers. |
| `pgp/EnrollmentSession.kt` | **New.** Holds the opened private key for the unlock session; cleared on lock. |
| `security/SecuritySettingsActivity.kt:242` | **Modify.** HLP teardown ordering. |
| `security/SecurityWipe.kt` | **Modify.** Add a named teardown `step(...)`. |

> **Spec gap found while planning, now closed here.** The spec's component table lists `EnrollmentStateClient` but omits the two clients the ceremony also needs — publishing the public key and fetching the envelope. Task 5 covers all three in `EnrollmentClients.kt`. Fold this back into the spec when the plan is approved.

---

### Task 1: HKDF and envelope opening (pure JVM)

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/DeviceEnvelope.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/DeviceEnvelopeTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray`
  - `internal data class DeviceEnvelopeFields(val epk: ByteArray, val iv: ByteArray, val ct: ByteArray)`
  - `internal fun parseDeviceEnvelope(json: String): DeviceEnvelopeFields?` — null on any malformed or unsupported input
  - `internal fun deviceEnvelopeAad(deviceId: String, pgpFingerprint: String): ByteArray`
  - `internal fun openDeviceEnvelope(sharedSecret: ByteArray, ownRawPublicKey: ByteArray, fields: DeviceEnvelopeFields, aad: ByteArray): String?` — null when GCM authentication fails

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/DeviceEnvelopeTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
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
    fun aad_isTheExactContractString() {
        val aad = deviceEnrollmentAadFixture()
        assertEquals("kypost-device-envelope/v1|dev-1|ABCD1234", String(aad, Charsets.UTF_8))
    }

    @Test
    fun parse_rejectsAnUnsupportedVersion() {
        assertNull(parseDeviceEnvelope("""{"v":2,"alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":"AA==","iv":"AA==","ct":"AA=="}"""))
    }

    @Test
    fun parse_rejectsAnUnsupportedAlg() {
        assertNull(parseDeviceEnvelope("""{"v":1,"alg":"something-else","epk":"AA==","iv":"AA==","ct":"AA=="}"""))
    }

    @Test
    fun parse_rejectsGarbage() {
        assertNull(parseDeviceEnvelope("not json"))
    }

    /** Opening must succeed with the right AAD... */
    @Test
    fun open_returnsThePlaintext() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertEquals(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
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
        val key = hkdfSha256(FIXTURE_SECRET, FIXTURE_SALT, "kypost-device-envelope/v1".toByteArray(), 32)
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
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
./gradlew testDebugUnitTest --no-configuration-cache --tests "com.urlxl.mail.pgp.DeviceEnvelopeTest"
```

Expected: compile failure — `hkdfSha256`, `parseDeviceEnvelope`, `deviceEnvelopeAad`, `openDeviceEnvelope`, `DeviceEnvelopeFields` unresolved.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/DeviceEnvelope.kt`:

```kotlin
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
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
./gradlew testDebugUnitTest --no-configuration-cache --tests "com.urlxl.mail.pgp.DeviceEnvelopeTest"
```

Expected: 8 tests PASS.

- [ ] **Step 5: Prove the AAD tests are load-bearing**

Mutate, confirm red, revert:

1. Delete `cipher.updateAAD(aad)` from `openDeviceEnvelope` → `open_refusesAWrongDeviceId` and `open_refusesAWrongFingerprint` must both fail.
2. Change the HKDF salt from `ownRawPublicKey` to `fields.epk` → `open_returnsThePlaintext` must fail.
3. Change `ENVELOPE_INFO` by one character → `open_returnsThePlaintext` must fail.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/DeviceEnvelope.kt \
        app/src/test/java/com/urlxl/mail/pgp/DeviceEnvelopeTest.kt
git commit -m "enrollment: open the device envelope, with the AAD binding enforced"
```

---

### Task 2: The enrollment keypair

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentKeyStore.kt`
- Test: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentKeyStoreTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `internal object EnrollmentKeyStore`
  - `fun newKeyPair(): Boolean` — generates if absent; false if generation is impossible
  - `fun rawPublicKey(): ByteArray?` — the 65-byte SEC1 point, null if absent
  - `fun encodedPublicKey(): String?` — base64 of the above, 88 chars
  - `fun sharedSecret(epk: ByteArray): ByteArray?` — ECDH against the ephemeral key
  - `fun deleteKeyPair()`
  - `const val ALIAS = "kypost_device_enrollment_agree"`

Instrumented, because Keystore is not available on the JVM.

- [ ] **Step 1: Write the failing tests**

Create `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentKeyStoreTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class EnrollmentKeyStoreTest {

    @Before fun clean() = EnrollmentKeyStore.deleteKeyPair()
    @After fun cleanup() = EnrollmentKeyStore.deleteKeyPair()

    @Test
    fun generatesAnUncompressedSec1Point() {
        assertTrue(EnrollmentKeyStore.newKeyPair())

        val raw = EnrollmentKeyStore.rawPublicKey()
        assertNotNull(raw)
        assertEquals(65, raw!!.size)
        assertEquals(0x04.toByte(), raw[0])
        assertEquals(88, EnrollmentKeyStore.encodedPublicKey()!!.length)
    }

    /** The whole design rests on this: an attacker holding the sealed envelope must not be able to
     *  obtain the key that opens it. */
    @Test
    fun thePrivateHalfCannotBeExported() {
        EnrollmentKeyStore.newKeyPair()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(EnrollmentKeyStore.ALIAS, null) as KeyStore.PrivateKeyEntry

        // A Keystore private key never yields raw material: getEncoded() returns null.
        assertEquals(null, entry.privateKey.encoded)
    }

    @Test
    fun ensureKeyPairIsIdempotent() {
        EnrollmentKeyStore.newKeyPair()
        val first = EnrollmentKeyStore.rawPublicKey()!!
        EnrollmentKeyStore.newKeyPair()

        assertEquals(
            first.joinToString("") { "%02x".format(it) },
            EnrollmentKeyStore.rawPublicKey()!!.joinToString("") { "%02x".format(it) },
        )
    }

    /** Both sides of an ECDH must land on the same secret, or nothing decrypts. */
    @Test
    fun sharedSecretAgreesWithAPeer() {
        EnrollmentKeyStore.newKeyPair()
        val peer = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val ours = EnrollmentKeyStore.sharedSecret(rawSec1(peer.public as java.security.interfaces.ECPublicKey))
        assertNotNull(ours)
        assertEquals(32, ours!!.size)
    }

    private fun rawSec1(key: java.security.interfaces.ECPublicKey): ByteArray {
        val x = key.w.affineX.toByteArray().takeLast(32).toByteArray()
        val y = key.w.affineY.toByteArray().takeLast(32).toByteArray()
        return byteArrayOf(0x04) + ByteArray(32 - x.size) + x + ByteArray(32 - y.size) + y
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./gradlew connectedDebugAndroidTest --no-configuration-cache \
  -Pandroid.testInstrumentationRunnerArguments.class=com.urlxl.mail.pgp.EnrollmentKeyStoreTest
```

Expected: compile failure — `EnrollmentKeyStore` unresolved. **A device or emulator must be attached.**

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentKeyStore.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.ECPublicKey
import java.util.Base64
import javax.crypto.KeyAgreement

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/**
 * This device's enrollment keypair: EC P-256, `PURPOSE_AGREE_KEY`, private half non-extractable.
 *
 * **No user-authentication requirement, deliberately.** This key only ever opens the server's
 * 7-day transport copy of the envelope, during a foreground ceremony with the user present.
 * Gating it would add a prompt that protects nothing durable — the durable protection is
 * [EnrollmentVault]'s re-seal key, which does carry the requirement. Conflating the two would
 * force the weaker requirement onto the key that matters.
 */
internal object EnrollmentKeyStore {

    const val ALIAS = "kypost_device_enrollment_agree"

    fun newKeyPair(): Boolean {
        if (keyStore().containsAlias(ALIAS)) return true
        return generate(strongBox = true) || generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
        true
    }.getOrElse {
        // StrongBox is absent on a large share of supported hardware. Falling back to the TEE is
        // the right trade: refusing enrollment there would exclude those users for a marginal gain.
        if (strongBox) Log.i("EnrollmentKeyStore", "StrongBox unavailable, falling back to TEE")
        else Log.e("EnrollmentKeyStore", "Could not generate the enrollment keypair", it)
        false
    }

    /** The uncompressed SEC1 point, `0x04 ‖ X ‖ Y` with each coordinate left-padded to 32 bytes.
     *  Built from [ECPublicKey.getW]; `getEncoded()` would give DER, which is the wrong contract. */
    fun rawPublicKey(): ByteArray? = runCatching {
        val cert = keyStore().getCertificate(ALIAS) ?: return null
        val w = (cert.publicKey as ECPublicKey).w
        byteArrayOf(0x04) + pad32(w.affineX) + pad32(w.affineY)
    }.getOrNull()

    fun encodedPublicKey(): String? = rawPublicKey()?.let { Base64.getEncoder().encodeToString(it) }

    fun sharedSecret(epk: ByteArray): ByteArray? = runCatching {
        val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val peer = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(
                java.security.spec.ECPoint(
                    BigInteger(1, epk.copyOfRange(1, 33)),
                    BigInteger(1, epk.copyOfRange(33, 65)),
                ),
                (entry.certificate.publicKey as ECPublicKey).params,
            ),
        )
        KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE).run {
            init(entry.privateKey)
            doPhase(peer, true)
            generateSecret()
        }
    }.getOrNull()

    fun deleteKeyPair() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    private fun pad32(v: BigInteger): ByteArray {
        val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - b.size) + b
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
./gradlew connectedDebugAndroidTest --no-configuration-cache \
  -Pandroid.testInstrumentationRunnerArguments.class=com.urlxl.mail.pgp.EnrollmentKeyStoreTest
```

Expected: 4 tests PASS.

- [ ] **Step 5: Prove the non-extractability test is load-bearing**

This one cannot be mutated by weakening the Keystore — `AndroidKeyStore` keys are never exportable. Instead, prove the test would catch a *design* regression: temporarily change `rawPublicKey()` to generate a software keypair via `KeyPairGenerator.getInstance("EC")` without the Keystore provider, and confirm `thePrivateHalfCannotBeExported` fails because `encoded` is non-null. Revert.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentKeyStore.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentKeyStoreTest.kt
git commit -m "enrollment: hold the agreement keypair in the secure element"
```

---

### Task 3: The re-seal vault

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentVault.kt`
- Test: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentVaultTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `internal class EnrollmentVault(context: Context)`
  - `fun ensureKey(): Boolean` — false when there is no secure lock screen
  - `fun sealCipher(): Cipher?` / `fun openCipher(iv: ByteArray): Cipher?` — for `BiometricPrompt.CryptoObject`
  - `fun store(iv: ByteArray, ciphertext: ByteArray)` / `fun stored(): Pair<ByteArray, ByteArray>?`
  - `fun hasBlob(): Boolean`
  - `fun destroy()`
  - `companion object { const val ALIAS = "kypost_device_envelope_seal"; const val PREFS_FILE = "device_envelope_secure" }`

- [ ] **Step 1: Write the failing tests**

Create `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentVaultTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.security.keystore.KeyInfo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

@RunWith(AndroidJUnit4::class)
class EnrollmentVaultTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    @Before fun clean() = vault.destroy()
    @After fun cleanup() = vault.destroy()

    /** The property the whole re-seal buys. If this key could be used without the device lock
     *  screen, an extracted device image would open the envelope. */
    @Test
    fun theKeyRequiresUserAuthentication() {
        assertTrue(vault.ensureKey())

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(EnrollmentVault.ALIAS, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo

        assertTrue("key must require user authentication", info.isUserAuthenticationRequired)
    }

    @Test
    fun storesAndReadsBackTheBlob() {
        vault.ensureKey()
        assertFalse(vault.hasBlob())

        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })

        assertTrue(vault.hasBlob())
        val (iv, ct) = vault.stored()!!
        assertNotNull(iv)
        assertTrue(ct.size == 40)
    }

    @Test
    fun destroyRemovesBothTheKeyAndTheBlob() {
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(40))

        vault.destroy()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse(vault.hasBlob())
        assertNull(vault.stored())
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./gradlew connectedDebugAndroidTest --no-configuration-cache \
  -Pandroid.testInstrumentationRunnerArguments.class=com.urlxl.mail.pgp.EnrollmentVaultTest
```

Expected: compile failure — `EnrollmentVault` unresolved.

> **The device running these tests must have a secure lock screen set.** `ensureKey()` returns false without one, by design, and `theKeyRequiresUserAuthentication` will fail with a confusing message. Set a PIN on the emulator first.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentVault.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_IV = "envelope_iv"
private const val KEY_CT = "envelope_ct"

/**
 * The durable half: an AES-256-GCM Keystore key that requires the device lock screen, and the
 * envelope re-sealed under it.
 *
 * The allowed authenticators include `DEVICE_CREDENTIAL` on purpose, so the key **survives a
 * biometric enrollment change**. Biometric-only would invalidate it whenever a fingerprint is
 * added, costing every ordinary user a full re-enrollment ceremony; and enrolling a biometric
 * already requires the device credential, so the attacker it would exclude already holds what this
 * key accepts. It also keeps `encryptionEnrolled` from flapping false for benign reasons — a marker
 * that cries wolf is one users learn to dismiss.
 *
 * The strict posture is not a switch here. It is Hostile Location Protection, under which there is
 * no envelope at all.
 */
internal class EnrollmentVault(context: Context) {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildPrefs() }

    /** False when the device has no secure lock screen. That is the honest outcome: the envelope's
     *  protection *is* the lock screen, so a device without one cannot hold a meaningful one. */
    fun ensureKey(): Boolean {
        if (runCatching { keyStore().containsAlias(ALIAS) }.getOrDefault(false)) return true
        return generate(strongBox = true) || generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            // 0 = per-use auth, satisfied through a BiometricPrompt.CryptoObject.
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
        true
    }.getOrElse {
        if (strongBox) Log.i("EnrollmentVault", "StrongBox unavailable, falling back to TEE")
        else Log.e("EnrollmentVault", "Could not generate the vault key", it)
        false
    }

    fun sealCipher(): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secretKey()) }
    }.getOrNull()

    fun openCipher(iv: ByteArray): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv)) }
    }.getOrNull()

    fun store(iv: ByteArray, ciphertext: ByteArray) {
        prefs.edit()
            .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .commit()
    }

    fun stored(): Pair<ByteArray, ByteArray>? {
        val iv = prefs.getString(KEY_IV, null) ?: return null
        val ct = prefs.getString(KEY_CT, null) ?: return null
        return Base64.decode(iv, Base64.NO_WRAP) to Base64.decode(ct, Base64.NO_WRAP)
    }

    fun hasBlob(): Boolean = prefs.contains(KEY_CT)

    /** Its own prefs file, not SecurePairingStore's, so this is a file delete plus one alias
     *  removal — separately assertable, and with no risk of clearing pairing state that Hostile
     *  Location Protection explicitly preserves. */
    fun destroy() {
        runCatching { prefs.edit().clear().commit() }
        runCatching { appContext.deleteSharedPreferences(PREFS_FILE) }
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    internal fun secretKey(): SecretKey = keyStore().getKey(ALIAS, null) as SecretKey

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun buildPrefs(): SharedPreferences {
        val masterKey = MasterKey.Builder(appContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            appContext,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    companion object {
        const val ALIAS = "kypost_device_envelope_seal"
        const val PREFS_FILE = "device_envelope_secure"
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Same command as Step 2. Expected: 3 tests PASS.

- [ ] **Step 5: Prove the auth test is load-bearing**

Remove `.setUserAuthenticationRequired(true)` and its parameters → `theKeyRequiresUserAuthentication` must fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentVault.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentVaultTest.kt
git commit -m "enrollment: re-seal the envelope behind the device lock screen"
```

---

### Task 4: The enrollment-state probe

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentState.kt`
- Test: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentStateTest.kt`

**Interfaces:**
- Consumes: `EnrollmentVault` from Task 3.
- Produces:
  - `internal enum class EnrollmentStatus { ENROLLED, NO_KEY, KEY_INVALIDATED, NO_BLOB }`
  - `internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus`
  - `internal fun EnrollmentStatus.isEnrolled(): Boolean`

> **This task settles the spec's one unverified assumption.** `Cipher.init` against a per-use auth-bound key is expected to succeed without user authentication and to throw `KeyPermanentlyInvalidatedException` only when the key is genuinely dead. If the instrumented test shows `init` demanding auth on this hardware, **stop and report it** — the fallback is to probe where possible and treat a cached `true` as unverified, never the reverse.

- [ ] **Step 1: Write the failing tests**

Create `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentStateTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollmentStateTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    @Before fun clean() = vault.destroy()
    @After fun cleanup() = vault.destroy()

    @Test
    fun noKeyReportsNotEnrolled() {
        assertEquals(EnrollmentStatus.NO_KEY, probeEnrollment(vault))
    }

    /** A key with no sealed blob is not enrollment. This is the app-reinstall shape: the Keystore
     *  can be repopulated while the blob is gone. */
    @Test
    fun keyWithoutBlobReportsNotEnrolled() {
        vault.ensureKey()
        assertEquals(EnrollmentStatus.NO_BLOB, probeEnrollment(vault))
    }

    /**
     * The load-bearing case: a healthy, merely-locked key must report ENROLLED **without any user
     * authentication**, because this probe runs from a background worker where nothing can show a
     * prompt. If this fails, the spec's decision 4 needs revisiting before the reporting path is
     * trusted — see the note in this task.
     */
    @Test
    fun healthyLockedKeyReportsEnrolledWithoutAPrompt() {
        vault.ensureKey()
        vault.store(ByteArray(12) { 3 }, ByteArray(48) { 4 })

        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))
    }

    /** Follows reality DOWN, not just up. */
    @Test
    fun destroyedKeyReportsNotEnrolled() {
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))
        vault.destroy()

        assertEquals(EnrollmentStatus.NO_KEY, probeEnrollment(vault))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./gradlew connectedDebugAndroidTest --no-configuration-cache \
  -Pandroid.testInstrumentationRunnerArguments.class=com.urlxl.mail.pgp.EnrollmentStateTest
```

Expected: compile failure — `probeEnrollment` unresolved.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentState.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, NO_KEY, KEY_INVALIDATED, NO_BLOB }

internal fun EnrollmentStatus.isEnrolled(): Boolean = this == EnrollmentStatus.ENROLLED

/**
 * Whether this device can still open its local envelope — reported to the server as
 * `encryptionEnrolled`, and rendered by the browser as "this device can read your encrypted mail".
 *
 * Probes the **keystore**, not our own bookkeeping. A cached boolean would survive an app reinstall
 * or a biometric-enrollment change, both of which destroy the key without any code of ours running,
 * and the Security page would then tell the user a device can read their mail when it can read
 * nothing.
 *
 * Uses `Cipher.init`, which needs no user authentication: this runs from a background worker where
 * nothing can show a prompt. A key that is merely locked initialises fine; only a permanently
 * invalidated one throws.
 */
internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus {
    val stored = vault.stored()
    return try {
        vault.secretKey()
        if (stored == null) EnrollmentStatus.NO_BLOB
        else if (vault.openCipher(stored.first) == null) EnrollmentStatus.KEY_INVALIDATED
        else EnrollmentStatus.ENROLLED
    } catch (e: KeyPermanentlyInvalidatedException) {
        EnrollmentStatus.KEY_INVALIDATED
    } catch (e: Exception) {
        EnrollmentStatus.NO_KEY
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Same command. Expected: 4 tests PASS. **If `healthyLockedKeyReportsEnrolledWithoutAPrompt` fails, stop and report before continuing.**

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentState.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentStateTest.kt
git commit -m "enrollment: probe the keystore for enrollment state, not a cached flag"
```

---

### Task 5: The three device-authed clients

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentClients.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentClientsTest.kt`

**Interfaces:**
- Consumes: `pairingAuthHeaders`, `executeSync`, `pairingHttpClient` from `com.urlxl.mail`; `FakeCallFactory` and `response(request, body, code)` from the existing test package.
- Produces:
  - `internal sealed class EnrollmentCallResult { object Ok; data class Envelope(val envelope: String); object NotFound; object Unauthorized; data class RateLimited(val retryAfterSeconds: Long?); data class Failed(val message: String) }`
  - `internal class EnrollmentClients(callFactory: Call.Factory = pairingHttpClient())`
  - `suspend fun publishKey(serverUrl: String, deviceId: String, deviceSecret: String, encodedPublicKey: String): EnrollmentCallResult`
  - `suspend fun fetchEnvelope(serverUrl: String, deviceId: String, deviceSecret: String): EnrollmentCallResult`
  - `suspend fun reportState(serverUrl: String, deviceId: String, deviceSecret: String, enrolled: Boolean): EnrollmentCallResult`

- [ ] **Step 1: Write the failing tests**

Create `app/src/test/java/com/urlxl/mail/pgp/EnrollmentClientsTest.kt`:

```kotlin
package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentClientsTest {

    @Test
    fun publishKey_sendsDeviceHeadersAndTheKey() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.publishKey("https://relay.example.com/", "dev-1", "secret-1", "BASE64KEY")

        assertEquals(EnrollmentCallResult.Ok, result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-key", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("dev-1", sent.header("X-Kypost-Device-Id"))
        assertEquals("secret-1", sent.header("X-Kypost-Device-Secret"))
    }

    /** No slot parameter exists on this route — the server builds it from the verified credential.
     *  A client that invented one would be coding against a contract that does not exist. */
    @Test
    fun fetchEnvelope_takesNoSlotParameter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"slot":"device:dev-1","envelope":"ENV"}""", 200)
        }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.fetchEnvelope("https://relay.example.com", "dev-1", "secret-1")

        assertEquals(EnrollmentCallResult.Envelope("ENV"), result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/envelope", sent.url.toString())
        assertTrue("no query string may be sent", sent.url.querySize == 0)
    }

    /** 404 covers both "never sealed" and "expired", indistinguishable by design. Both mean
     *  re-run the ceremony, so they must map to one result the caller cannot accidentally split. */
    @Test
    fun fetchEnvelope_mapsNotFound() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"error":"no envelope sealed for this device"}""", 404)
        }

        assertEquals(
            EnrollmentCallResult.NotFound,
            EnrollmentClients(callFactory = factory).fetchEnvelope("https://relay.example.com", "d", "s"),
        )
    }

    @Test
    fun reportState_sendsTheBooleanAsRequired() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        clients.reportState("https://relay.example.com", "dev-1", "secret-1", enrolled = false)

        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-state", sent.url.toString())
        val body = okio.Buffer().also { sent.body!!.writeTo(it) }.readUtf8()
        assertTrue("must state an opinion explicitly: $body", body.contains("\"encryptionEnrolled\":false"))
    }

    /** Treated exactly as MfaResponseClient treats it — both come from the same shared
     *  writeDeviceAuthFailure on the server. */
    @Test
    fun rateLimited_carriesRetryAfter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, "", 429, headers = mapOf("Retry-After" to "42"))
        }

        assertEquals(
            EnrollmentCallResult.RateLimited(42L),
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", true),
        )
    }

    @Test
    fun unauthorized_isDistinctFromAGenericFailure() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, "", 401) }

        assertEquals(
            EnrollmentCallResult.Unauthorized,
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", true),
        )
    }
}
```

> If the existing `response(...)` helper in this test package does not accept a `headers` map, extend it there rather than duplicating it — it is shared by several client tests.

- [ ] **Step 2: Run to verify it fails**

```bash
./gradlew testDebugUnitTest --no-configuration-cache --tests "com.urlxl.mail.pgp.EnrollmentClientsTest"
```

Expected: compile failure — `EnrollmentClients` unresolved.

- [ ] **Step 3: Write the implementation**

Read `push/MfaResponseClient.kt` first and follow its shape — injectable `Call.Factory`, `executeSync`, structured error mapping — rather than inventing a second one.

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentClients.kt`:

```kotlin
package com.urlxl.mail.pgp

import com.urlxl.mail.executeSync
import com.urlxl.mail.pairingAuthHeaders
import com.urlxl.mail.pairingHttpClient
import com.urlxl.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

internal sealed class EnrollmentCallResult {
    object Ok : EnrollmentCallResult()
    data class Envelope(val envelope: String) : EnrollmentCallResult()
    /** 404 covers both "never sealed" and "expired" — indistinguishable by design, and both mean
     *  re-run the ceremony. One result so a caller cannot accidentally split them. */
    object NotFound : EnrollmentCallResult()
    object Unauthorized : EnrollmentCallResult()
    data class RateLimited(val retryAfterSeconds: Long?) : EnrollmentCallResult()
    data class Failed(val message: String) : EnrollmentCallResult()
}

/**
 * The three device-authenticated enrollment calls.
 *
 * Endpoints are built from the paired origin, never from a server-supplied URL — the same rule
 * `PgpKeyActivity.renderQr` follows, and for the same reason: a tampered response must not be able
 * to point an authenticated call at another host, outside the TLS pin.
 */
internal class EnrollmentClients(
    private val callFactory: Call.Factory = pairingHttpClient(),
) {

    suspend fun publishKey(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        encodedPublicKey: String,
    ): EnrollmentCallResult {
        val body = JSONObject().put("publicKey", encodedPublicKey).toString()
        return call(serverUrl, "/api/pgp/device/enrollment-key", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    suspend fun fetchEnvelope(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
    ): EnrollmentCallResult =
        // No slot parameter: the server builds it from the verified credential, and a test there
        // asserts a ?slot= query is ignored so the route cannot quietly grow one.
        call(serverUrl, "/api/pgp/device/envelope", deviceId, deviceSecret, body = null) { raw ->
            val envelope = runCatching { JSONObject(raw).getString("envelope") }.getOrNull()
            if (envelope.isNullOrBlank()) EnrollmentCallResult.Failed("Malformed envelope response")
            else EnrollmentCallResult.Envelope(envelope)
        }

    suspend fun reportState(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        enrolled: Boolean,
    ): EnrollmentCallResult {
        // Always written explicitly. This route requires the field — unlike the tri-state pointer
        // on registration, an absent value here is a 400, not "no opinion".
        val body = JSONObject().put("encryptionEnrolled", enrolled).toString()
        return call(serverUrl, "/api/pgp/device/enrollment-state", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    private suspend fun call(
        serverUrl: String,
        path: String,
        deviceId: String,
        deviceSecret: String,
        body: String?,
        onSuccess: (String) -> EnrollmentCallResult,
    ): EnrollmentCallResult {
        val url = pairingEndpoint(serverUrl, path)
            ?: return EnrollmentCallResult.Failed("Server URL is not valid")
        val request = Request.Builder()
            .url(url)
            .apply { if (body == null) get() else post(body.toRequestBody(JSON_MEDIA_TYPE)) }
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.header("Retry-After"))
            }
        }
        val (code, raw, retryAfter) = result.getOrNull()
            ?: return EnrollmentCallResult.Failed(result.exceptionOrNull()?.message ?: "Request failed")

        return when (code) {
            200 -> onSuccess(raw)
            401 -> EnrollmentCallResult.Unauthorized
            404 -> EnrollmentCallResult.NotFound
            429 -> EnrollmentCallResult.RateLimited(retryAfter?.toLongOrNull())
            else -> EnrollmentCallResult.Failed("Request failed ($code)")
        }
    }
}
```

`onSuccess` for `publishKey` and `reportState` ignores its argument; keeping one shared `call` is what stops the three from drifting apart in how they treat `401`/`429`.

- [ ] **Step 4: Run to verify it passes**

Same command. Expected: 6 tests PASS.

- [ ] **Step 5: Prove the header test is load-bearing**

Remove `.pairingAuthHeaders(deviceId, deviceSecret)` from `publishKey` → `publishKey_sendsDeviceHeadersAndTheKey` must fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentClients.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentClientsTest.kt
git commit -m "enrollment: add the three device-authed enrollment calls"
```

---

### Task 6: Teardown

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentTeardown.kt`
- Test: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentTeardownTest.kt`

**Interfaces:**
- Consumes: `EnrollmentKeyStore` (Task 2), `EnrollmentVault` (Task 3).
- Produces: `internal object EnrollmentTeardown { fun destroy(context: Context) }`

- [ ] **Step 1: Write the failing test**

```kotlin
package com.urlxl.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class EnrollmentTeardownTest {

    @Test
    fun destroysBothKeysAndTheBlob() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val vault = EnrollmentVault(context)
        EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        EnrollmentTeardown.destroy(context)

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("agreement key survived", ks.containsAlias(EnrollmentKeyStore.ALIAS))
        assertFalse("vault key survived", ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse("sealed blob survived", EnrollmentVault(context).hasBlob())
    }
}
```

- [ ] **Step 2: Run to verify it fails.** Expected: `EnrollmentTeardown` unresolved.

- [ ] **Step 3: Write the implementation**

```kotlin
package com.urlxl.mail.pgp

import android.content.Context

/**
 * Destroys everything that makes this device able to open its envelope.
 *
 * Two callers, both of which must survive interruption:
 *  - Enabling Hostile Location Protection. An envelope that survived that switch would leave the
 *    account's private key openable by device unlock on a device whose owner has just declared
 *    they are somewhere hostile — the exact disclosure the mode exists to prevent.
 *  - SecurityWipe, reached by too many wrong PIN attempts. A key surviving that would outlive a
 *    wipe nobody chose.
 */
internal object EnrollmentTeardown {
    fun destroy(context: Context) {
        EnrollmentVault(context).destroy()
        EnrollmentKeyStore.deleteKeyPair()
    }
}
```

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentTeardown.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentTeardownTest.kt
git commit -m "enrollment: tear down the envelope and both keys in one place"
```

---

### Task 7: The durable teardown report

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentStateWorker.kt`
- Test: `app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentStateWorkerTest.kt`

**Interfaces:**
- Consumes: `EnrollmentClients` (Task 5), `probeEnrollment` (Task 4), `SecurePairingStore`.
- Produces:
  - `internal class EnrollmentStateWorker(context: Context, params: WorkerParameters) : CoroutineWorker`
  - `companion object { fun enqueue(context: Context) }`

- [ ] **Step 1: Write the failing test**

Assert two things: that `enqueue` results in exactly one uniquely-named work request enqueued (use `WorkManagerTestInitHelper` and `WorkManager.getWorkInfosForUniqueWork`), and that the worker carries **no credential in its input data**:

```kotlin
@Test
fun enqueuedWorkCarriesNoCredentialInItsInput() {
    EnrollmentStateWorker.enqueue(context)

    val infos = WorkManager.getInstance(context)
        .getWorkInfosForUniqueWork(EnrollmentStateWorker.UNIQUE_NAME).get()
    assertEquals(1, infos.size)
    // WorkManager writes input data to its own database in plaintext. The credential is read at
    // run time from SecurePairingStore instead.
    assertTrue(infos.single().progress.keyValueMap.isEmpty())
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/urlxl/mail/pgp/EnrollmentStateWorker.kt`:

```kotlin
package com.urlxl.mail.pgp

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.urlxl.mail.push.PushRuntime
import java.util.concurrent.TimeUnit

/**
 * Reports enrollment state durably.
 *
 * Enqueued before Hostile Location Protection's flag flips, so an interrupted teardown still
 * corrects the server: the Security page would otherwise show this device as protected in the
 * window between, which is the specific lie the marker exists to prevent. Offline is the expected
 * case — the user just declared they are somewhere hostile — so this retries rather than dropping.
 */
internal class EnrollmentStateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Read at run time, never carried in inputData: WorkManager writes input to its own
        // database in plaintext, and this is the credential every authenticated call uses.
        val pairing = PushRuntime.graph(applicationContext).securePairingStore.pairingSnapshot(null)
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Unpaired: there is no device row left to correct. SecurityWipe's path lands here.
            return Result.success()
        }

        val enrolled = probeEnrollment(EnrollmentVault(applicationContext)).isEnrolled()

        return when (EnrollmentClients().reportState(pairing.serverUrl, deviceId, deviceSecret, enrolled)) {
            is EnrollmentCallResult.Ok -> Result.success()
            // The marker is now wrong in the unsafe direction. Keep trying.
            is EnrollmentCallResult.RateLimited, is EnrollmentCallResult.Failed -> Result.retry()
            // A credential the server refuses will not start working on retry.
            is EnrollmentCallResult.Unauthorized -> Result.failure()
            else -> Result.failure()
        }
    }

    companion object {
        const val UNIQUE_NAME = "kypost_enrollment_state_report"

        fun enqueue(context: Context) {
            val request = OneTimeWorkRequestBuilder<EnrollmentStateWorker>()
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context.applicationContext)
                .enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.REPLACE, request)
        }
    }
}
```

Check the accessor name on `PushRuntime.graph(...)` before writing this — if the graph exposes the store under a different property, use that rather than adding one.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentStateWorker.kt \
        app/src/androidTest/java/com/urlxl/mail/pgp/EnrollmentStateWorkerTest.kt
git commit -m "enrollment: report state through durable work, not a fire-and-forget call"
```

---

### Task 8: Wire teardown into both destructive paths

**Files:**
- Modify: `app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt:242-260`
- Modify: `app/src/main/java/com/urlxl/mail/security/SecurityWipe.kt` (add a step near `step("appLock")`, line ~313)
- Test: `app/src/androidTest/java/com/urlxl/mail/security/HostileLocationEnrollmentTeardownTest.kt`

**Interfaces:**
- Consumes: `EnrollmentTeardown.destroy` (Task 6), `EnrollmentStateWorker.enqueue` (Task 7).
- Produces: no new public API.

- [ ] **Step 1: Write the failing test**

Assert that after enabling HLP with an active enrollment, both keys and the blob are gone, the report work is enqueued, **and the pairing survives** — HLP keeps push and sync working, unlike a wipe:

```kotlin
@Test
fun enablingProtectionDestroysEnrollmentButKeepsThePairing() {
    // ... seed a pairing, EnrollmentKeyStore.newKeyPair(), vault.ensureKey(), vault.store(...)
    // ... invoke the same teardown sequence applyHostileLocationProtection runs
    assertFalse(ks.containsAlias(EnrollmentKeyStore.ALIAS))
    assertFalse(ks.containsAlias(EnrollmentVault.ALIAS))
    assertNotNull("HLP must not unpair the device", securePairingStore.pairingSnapshot(null))
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Modify `applyHostileLocationProtection`**

Insert into the existing `withContext(SecurityWork)` block, in exactly this order:

```kotlin
if (enable) {
    // Before the flag flips, so every interruption point is safe: a process death after this
    // leaves the flag off with the envelope already gone — honestly un-enrolled — rather than
    // protection on with a readable envelope, which is the state this mode exists to prevent.
    EnrollmentTeardown.destroy(this@SecuritySettingsActivity)
    // Durable, because the Security page would otherwise show this device as protected until the
    // next natural registration. Offline is the expected case here.
    EnrollmentStateWorker.enqueue(this@SecuritySettingsActivity)
}
settings.setEnabled(enable)
```

- [ ] **Step 4: Add the `SecurityWipe` step**

Beside `step("appLock")`:

```kotlin
step("enrollmentTeardown") { EnrollmentTeardown.destroy(appContext) }
```

A named step, so a failure lands in the incomplete-wipe list rather than being silently skipped. No worker on this path: the wipe deregisters and clears the pairing, so the device row goes away server-side.

- [ ] **Step 5: Run to verify it passes**, then run the existing wipe suite to confirm nothing regressed:

```bash
./gradlew connectedDebugAndroidTest --no-configuration-cache \
  -Pandroid.testInstrumentationRunnerArguments.class=com.urlxl.mail.security.WipeResurrectionTest
```

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/security/SecuritySettingsActivity.kt \
        app/src/main/java/com/urlxl/mail/security/SecurityWipe.kt \
        app/src/androidTest/java/com/urlxl/mail/security/HostileLocationEnrollmentTeardownTest.kt
git commit -m "security: destroy device enrollment on both destructive paths"
```

---

### Task 9: Session-scoped plaintext

**Files:**
- Create: `app/src/main/java/com/urlxl/mail/pgp/EnrollmentSession.kt`
- Test: `app/src/test/java/com/urlxl/mail/pgp/EnrollmentSessionTest.kt`

**Interfaces:**
- Consumes: nothing.
- Produces: `internal object EnrollmentSession { fun put(armoredKey: String); fun peek(): String?; fun clear() }`

The opened private key lives until the app locks — the same trigger the user already configured at "Lock after: …". Clearing must be wired into whatever `AppLockManager` calls when it locks; find that call site and add `EnrollmentSession.clear()` beside the existing teardown there.

- [ ] **Step 1: Write the failing test**

```kotlin
package com.urlxl.mail.pgp

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EnrollmentSessionTest {

    @After fun cleanup() = EnrollmentSession.clear()

    @Test
    fun holdsTheKeyForTheSession() {
        EnrollmentSession.put("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----", EnrollmentSession.peek())
    }

    @Test
    fun clearForgetsIt() {
        EnrollmentSession.put("secret")
        EnrollmentSession.clear()
        assertNull(EnrollmentSession.peek())
    }

    /** Zeroed in place, not merely dereferenced: a String's backing array cannot be wiped, so a
     *  heap dump taken after the app locked would still hold the private key. */
    @Test
    fun clearZeroesTheBackingArray() {
        EnrollmentSession.put("secret")
        val held = EnrollmentSession.backingArrayForTest()
        EnrollmentSession.clear()
        assertEquals("      ", String(held))
    }
}
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement**

```kotlin
package com.urlxl.mail.pgp

import androidx.annotation.VisibleForTesting

/**
 * Holds the opened PGP private key for one unlock session.
 *
 * The plaintext lifetime is the real exposure, not how often BiometricPrompt appears — so it is
 * bound to the window the user already configured at "Lock after: …" rather than to a second
 * concept of its own.
 *
 * Held as a CharArray so [clear] can zero it. A String's backing array cannot be wiped, so one
 * would survive in the heap until GC and beyond, in a dump taken after the app locked.
 */
internal object EnrollmentSession {

    @Volatile
    private var held: CharArray? = null

    fun put(armoredKey: String) {
        clear()
        held = armoredKey.toCharArray()
    }

    fun peek(): String? = held?.let { String(it) }

    fun clear() {
        held?.fill(' ')
        held = null
    }

    @VisibleForTesting
    fun backingArrayForTest(): CharArray = held!!
}
```

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Wire `clear()` into the app-lock path** and add a test asserting locking the app clears it.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/urlxl/mail/pgp/EnrollmentSession.kt \
        app/src/test/java/com/urlxl/mail/pgp/EnrollmentSessionTest.kt
git commit -m "enrollment: bound the opened key's lifetime to the app lock"
```

---

## Verification before calling this done

```bash
./gradlew testDebugUnitTest --no-configuration-cache
./gradlew connectedDebugAndroidTest --no-configuration-cache
```

Quote the actual counts. The unit suite was 512 tests / 0 failures at `e0f23a8`; it must be higher and still zero.

**Do not report success on the instrumented suite without a device attached and a secure lock screen set on it.** `EnrollmentVault.ensureKey()` returns false without one by design, and several tests will fail in a way that looks like a code defect but is not.

## Spec coverage check

| Spec requirement | Task |
|---|---|
| Two keystore keys, distinct auth requirements | 2, 3 |
| Envelope open with HKDF + AAD | 1 |
| AAD refuses wrong deviceId and wrong fingerprint | 1 |
| `Cipher.init` probe, no auth needed | 4 |
| Dedicated enrollment-state route | 5 + companion server plan |
| Transport-independent reporting | 5, 7 |
| HLP teardown ordering, safe under process death | 8 |
| SecurityWipe teardown as a named step | 8 |
| Teardown does not disturb pairing | 8 |
| Opened key lives until app locks | 9 |
| StrongBox falls back rather than failing | 2, 3 |
| No secure lock screen means no enrollment | 3 |
| Key survives biometric enrollment change | 3 |

**Not covered here, deliberately:** the ceremony's step ordering (publish key at enrollment start, enrollment must follow identity creation) needs an orchestrator that belongs with the UI in spec 2, since every one of its failure modes is something the user must be told about. Tests 7 and 8 from the handoff — re-registration sending the device secret, and enrollment-before-identity — land there. Flag this when spec 2 is written so they are not lost.
