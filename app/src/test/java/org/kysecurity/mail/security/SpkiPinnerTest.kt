package org.kysecurity.mail.security

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

// A real, valid self-signed X.509 certificate (subject/issuer CN=test), generated once with:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 3650 -subj "/CN=test"
// `sun.security.x509` internal JDK classes are not accessible from this project's unit-test JVM
// (JPMS blocks the `java.base` package export), so a hardcoded PEM stands in for in-process
// certificate minting. Only a genuine, parseable X509Certificate is required to exercise
// SpkiPinner.pinFor — how it was produced is not load-bearing.
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
}
