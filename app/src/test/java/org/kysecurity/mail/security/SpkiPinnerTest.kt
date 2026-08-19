package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

// Self-signed X.509 (CN=test) from: openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=test"
private const val TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUE6Qe6XIm8Bqo7G0+cLuyzRKKj3swDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA3MjIxOTUzNDFaFw0zNjA3MTkxOTUz
NDFaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDfTUaTJDPqXLJmGmXSKruwRXINM7aFz5Fl5Kigqa/i5ktwXUN9jkK9/zXA
lWZHY31lnCy4dOOJvyObIX/OPfRFxXixAH78s5MnucY9/iNCEpadB82hL/eidm9R
QJbf4DN53kITcdqed60Dv1UNhVDtYFAURA2bB7OWNZZ5BJzTIcXm8vo/9f1ASGff
eb702LoFhGqa2W7HlRiWNT+IybUJFC/YS5p60aVagqELs1a8dnD8lo+4PVSlKt8c
ChXs5CkAiQbxBq6IG96e36aguyQIM7NEvB3XzoG/9R6UDWwI5xM4U79b+8KzzjtC
TgYzMWAtpalZobJkiINqu2BBFPGHAgMBAAGjUzBRMB0GA1UdDgQWBBQ9GCHFPtA1
Qsn910vQG7Zq6WCfqDAfBgNVHSMEGDAWgBQ9GCHFPtA1Qsn910vQG7Zq6WCfqDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCFhY8GXovQiMWsMh9P
at9aEZaEW6jj4dEYunA6rdx8pIkNYsUInlZaf3e/r4gV1KYam1HjksqjZcIx/OLt
+PQSiliE85eo5yKkqjTUkAcfq949EK6Ro6E1vwsexWoKhkxr3pLD7BiVvHs8mYhC
nuDmvJ4vp9ZmHWd0I7nJVD7yNbFFo0dA1IudlPIwyRyWxs6sJ6nuX0VXsx0X27bK
Dz2zzpPDks3uI3gugUOsU1E4cgZaRmQXrGI0BeTY9xWKLwc6x0FVrTAk/t8WKdzq
mazZcakEoew6O+YDEZ4A2llo4FE/9P4vmou++GpXCvpdKQ9KX7ccjJ9enWCiF2Br
fdaR
-----END CERTIFICATE-----"""

private fun selfSignedTestCertificate(): X509Certificate {
    val factory = CertificateFactory.getInstance("X.509")
    return factory.generateCertificate(ByteArrayInputStream(TEST_CERT_PEM.toByteArray())) as X509Certificate
}

// A real two-certificate chain: a self-issued root and a leaf the root signed. Generated once with
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -subj "/CN=KyPost Test Root"
//   openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -out leaf.pem
// and embedded, matching TEST_CERT_PEM above: pinsForChain's rule is about issuer/subject
// identity, and no fixture short of a real chain can exercise that.
private const val LEAF_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDCDCCAfCgAwIBAgIUZiSRmJK38BjGDurrvPg8Pr34PKUwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQS3lQb3N0IFRlc3QgUm9vdDAeFw0yNjA4MTkxMjM2MzVa
Fw0zNjA4MTYxMjM2MzVaMB0xGzAZBgNVBAMMEnJlbGF5LnRlc3QuaW52YWxpZDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQUp3ud8+RODA5G2pwY8PSH
fp2kztjmWEAmUsOHQPdI/ykxWOb1K1swgSm2HCy5Kdr+OU3KaQSXcEjVn/7KiD0/
q6/mgWbPBbQL4eVsjDGhGWEcrtaA1qQewGzroo7+bqQXq/hbRup+tS42NEfPLKkp
wtTmvOr/swHiSDFPHzPhHNR8GrzWg1HYFDoWCDWgqvTkd7sLpePIL33yfaLtzo00
P5Z0f96B63G+wuLIyXxJX7Yzy7v6mfbygtIEisnSAGZ3qpanUvAndqQAxJlJBcYU
guA9zI1WFys5l/IoEpQeY8KFPj+XhwKReYzytcCR42sep6A5tF7eQ/Tcdibp/q0C
AwEAAaNCMEAwHQYDVR0OBBYEFOtBh60X800LLRpZ++oJ8TPyJLuAMB8GA1UdIwQY
MBaAFNtMdl9Tt7PzbL3CgKym84uWGFejMA0GCSqGSIb3DQEBCwUAA4IBAQBj6V/P
xujiMUbvRVjG2lAZumKlqbfBlEdN6bQXPOZW70URIqHQPx/gyY5RwC9qPGf9dJFm
PE556X3jc+Ju29aj2+2ZNEueyfHb1j7zL7fz5X1uyuTH4VIkCp4Oy0Lwg4eVQ12D
J+rkj3xfSqiJUB5hAReJmTSZDt0OS6GyPUVUCUZ+80fEy9dNwbbl7GFAo0DymQcr
6gF588HsLhEYLMJSbcnBfFAfPsnGU3ohUZQCO284oileHLV08dJ8OzfttgOWaYHf
4rO78ChN+sSvkFsIqDT2K3ZnjeEVwxP5VJliaMeFi6ZTBrtw2nFRrPc69CfcvPxC
kJ77Uth/Erg7jqvZ
-----END CERTIFICATE-----"""

private const val ROOT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUfOpIcwCtV4ADYH4afuZk+MgUVfkwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQS3lQb3N0IFRlc3QgUm9vdDAeFw0yNjA4MTkxMjM2MzVa
Fw00NjA4MTQxMjM2MzVaMBsxGTAXBgNVBAMMEEt5UG9zdCBUZXN0IFJvb3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtYotF3D/jzz5SXqdg1cY9hPH/
5R2AFXW0Osh7gu8TwFPbhUcjgKHfQ7ZyB/sAiPKmN12YbCt8gMY8u8a9gqkymVwk
ueyONFxQ972crK3fe1zb5szU4tKN7kwJhAqCGc5v1l9xtbt2BcfoqXVK2/Q4V6iM
2MV9foJGY80NLnXOAg1mQNukOJa5mScGw1rkHsQMtUyBRTbpgx21S9rWQtCnTtA+
5L3MHb22RNXh5AIGx11f9PEMMvaIdPAKHZgwaqslksTTAQpUQbKCRy+dghxSEHEW
D1HNewVyosjdyZR237/ft+jM/F2O0/1OTE6lZtIbnL2PxjIQepV9EjG835n/AgMB
AAGjUzBRMB0GA1UdDgQWBBTbTHZfU7ez82y9woCspvOLlhhXozAfBgNVHSMEGDAW
gBTbTHZfU7ez82y9woCspvOLlhhXozAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQB+AAWg9PansyHoFt6zfDqRMqRflgp2xeml/8UjtxDuMryTgm8k
KoB4u3lbgRF2eIgXx5lRLsX3cK5us+3r5FL5CMamg14PwTAxfqORfr6bkQUBRCwY
ClOD9eN1E4rzFqTVE16iVcBqdQAz4Tpiq6r5gZSjCMX7tsrt5sxN5MIG5dN3lQML
bbVFyuPHBHDKT4aXA0csw2H+MhGUKZqkXnLD+h9ANRUplMKE7LVyURK9sNCw6LDi
B3W/DhrjuSPxbTIanPMCNUFZodMJpT0E4uF6ESfZ5XKfeTcCD3uyOtkbBEaKfaOy
CGknzaYSAKda2Go1B2mBiBbi7aWimQ+QkkPD
-----END CERTIFICATE-----"""

private fun certificateOf(pem: String): X509Certificate =
    CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(pem.toByteArray())) as X509Certificate

class SpkiPinnerTest {
    @Test
    fun pinFor_returnsSha256PinStringFormat() {
        val pin = SpkiPinner.pinFor(selfSignedTestCertificate())
        assertTrue(pin.startsWith("sha256/"))
    }

    @Test
    fun pinFor_isStable_forTheSameCertificate() {
        val cert = selfSignedTestCertificate()
        assertTrue(SpkiPinner.pinFor(cert) == SpkiPinner.pinFor(cert))
    }

    @Test
    fun pinsForChain_excludesTheTrustAnchor() {
        val leaf = certificateOf(LEAF_CERT_PEM)
        val root = certificateOf(ROOT_CERT_PEM)

        val pins = SpkiPinner.pinsForChain(listOf(leaf, root))

        // The whole finding: CertificatePinner passes on ANY chain member, so a pinned public root
        // admits every certificate that root has ever issued. Pinning it is not pinning.
        assertTrue("the leaf must be pinned", SpkiPinner.pinFor(leaf) in pins)
        assertFalse("the trust anchor must NOT be pinned", SpkiPinner.pinFor(root) in pins)
        assertEquals(1, pins.size)
    }

    @Test
    fun pinsForChain_keepsIntermediates() {
        // The leaf here stands in for an intermediate: what matters is that it is not self-issued,
        // which is exactly the property that distinguishes an intermediate from a root.
        val intermediate = certificateOf(LEAF_CERT_PEM)
        val root = certificateOf(ROOT_CERT_PEM)

        val pins = SpkiPinner.pinsForChain(listOf(intermediate, root))

        // Pinning issuers alongside the leaf is what lets a routine renewal keep validating; only
        // the anchor is dropped, not "everything but the leaf".
        assertTrue(SpkiPinner.pinFor(intermediate) in pins)
    }

    @Test
    fun pinsForChain_pinsAWhollySelfSignedChain() {
        // A self-hosted relay presenting one self-signed certificate. Filtering anchors would leave
        // nothing to pin, and an empty pin set is worse than none: CertificatePinner passes
        // vacuously for a host with no configured pin. Fall back to the chain as given.
        val selfSigned = selfSignedTestCertificate()

        val pins = SpkiPinner.pinsForChain(listOf(selfSigned))

        assertEquals(setOf(SpkiPinner.pinFor(selfSigned)), pins)
    }

    @Test
    fun pinsForChain_isEmptyForAnEmptyChain() {
        // TlsPin's `require` refuses an empty set; the caller must see empty rather than be handed
        // a pin set that pins nothing.
        assertTrue(SpkiPinner.pinsForChain(emptyList()).isEmpty())
    }
}
