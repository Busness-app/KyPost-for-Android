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

// A real THREE-certificate chain: a self-issued root, an intermediate it signed, and a leaf the
// intermediate signed. Generated once with openssl and embedded, because the rule under test is
// about which link in a real chain gets pinned and no synthetic fixture can stand in for that.
// Verified at generation time with: openssl verify -CAfile root.pem -untrusted int.pem leaf.pem
private const val LEAF_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDPTCCAiWgAwIBAgIUPrt+Z8RyJyXFMhLx/jxlJc9rNZQwDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYS3lQb3N0IFRlc3QgSW50ZXJtZWRpYXRlMB4XDTI2MDgx
OTE0MTc0MVoXDTM2MDgxNjE0MTc0MVowHTEbMBkGA1UEAwwScmVsYXkudGVzdC5p
bnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgex9eCSfj84w
203cipfG1CFTScv86+H4hjTmGNlGUIgXB3VYssn8zLgE3P85Uavj3Mk2lfyXCKfq
UNxhuwGUop0kfqBLXlfCasoYaxtKfa+nxNmWU/tb9/Y140BBwVEOXI5DT/KYpRAf
e4ETsBiyCXVn1Fyo7t9sb7mv5pUGeeGef0IjIe7j0ig+SusQZofWb/cghxPPt7Ba
YsO/ZQLAc2l0Ei8t0zO61qx1Rq23ng7jiJBKpzSk3fj55oZqOIzP8+7bRiql8ZDC
oEajnKx/Lg8uSkHwmlTMpAK0Crc7Y0seoYQjfORMiyZLBsOsMNlNfDdzzRhbAhZu
tVuyf3YtGwIDAQABo28wbTAMBgNVHRMBAf8EAjAAMB0GA1UdEQQWMBSCEnJlbGF5
LnRlc3QuaW52YWxpZDAdBgNVHQ4EFgQUrCaRmB5IDyNDNS/DhzmljgT9eKowHwYD
VR0jBBgwFoAUeAz//y78dudZHnyDAt3rXU6BYUIwDQYJKoZIhvcNAQELBQADggEB
ABanDkWf14igft0qAbO3CyAoVdO7vEZ6MtJsUcVmTcgbpSRYY6E03Nequ8gyHe7S
JtlYf1wHC3Vwsif0VjxQoq+fIxXsN9eUqgD4+mVSuGoiFv/q023iorRfeGX8YsN7
6n5ABBPnOz9rM4yM/2rPeEGmD2ErF0fgCAskCvy41PBkgQFd5Pjv3f3+tb48r3zy
n1bpamq6pYriZv1bP++T4yWA0/MCvXv0zaQMkYzB+8xKHCqZSQ6s4ns3oXOtNwX3
w/GxyHJQpqAB/6NDfZvkmZ3yy0w+tQ61356/laazfFSN5RZYp5GhL2DG9EQVtx52
CdvEuErSk+blPXRRjddqgyU=
-----END CERTIFICATE-----"""

private const val INTERMEDIATE_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUCLCzNFVKZnvOPl0FcU7lrxf86IAwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQS3lQb3N0IFRlc3QgUm9vdDAeFw0yNjA4MTkxNDE3NDFa
Fw0zNjA4MTYxNDE3NDFaMCMxITAfBgNVBAMMGEt5UG9zdCBUZXN0IEludGVybWVk
aWF0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOEfHNyjQAA5qEL1
8rW5vLSgrqQzC8lKZVb/0wcjmLh+tUEoPOXgGT9+HEAOhIjZ2axPsikrEGpIjNOM
yBrgReRcJXKvms78yTf9pa4kTfeP/WsWhgCFXDd5zVUkujAFpOcAu2vijND6rmX9
iSXi+XdZ3KdlFdXtZ5vyX+143CYeaDFwfdWVhzv1NLTdjV2tWe7mLM+8QE8wFnpZ
+kWpKEymRgXZ+YHvag5H3Wcl8XAhPbZmgss2CNCGn9gcQck2pLiqw9s6DXp7ElbT
F2jUXtmE8X9DSTBPaMp4IUX/PJejvmFKEzHEU10s2CI3/oQTEEYioTwgv0JZWNTO
lX1x+mUCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
HQYDVR0OBBYEFHgM//8u/HbnWR58gwLd611OgWFCMB8GA1UdIwQYMBaAFNNZN//A
14qPJBVtNtl0MzAKMQoxMA0GCSqGSIb3DQEBCwUAA4IBAQCRFleb7Ay+U+iJMEPc
7NHLHXQDgg/EEBsFVGKG0XHnhrd631zv6izind2Buq6Ol0u1SymzEtaZPmqqQHy7
ZOig8H1n5s8xwOinOL/X0Eaas3AWzPtf94Q/wfh+BSuUKBQag6EFoZ7Jj1R4rCg+
25g2VE73w4VZC17XP46PsyfeLXVfnpxINBSktf32iKEJD7bBWWrn3+NpcZ4xsWtQ
mclNL4Px26P0v9uoOqogT2/GYOBL3HzpTrs9YbQr3/G18CyQscMemdqI/zcIdEt4
0MsJX90cpSIlIOuZWfS2lDtpFPtkuwq5yxdiwpmX7hpeVb1cnP4keUU1z7MzyU1y
72cf
-----END CERTIFICATE-----"""

private const val ROOT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUMgIgO8M6JKLOq57IEBRlfcdDRQ8wDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQS3lQb3N0IFRlc3QgUm9vdDAeFw0yNjA4MTkxNDE3NDFa
Fw00NjA4MTQxNDE3NDFaMBsxGTAXBgNVBAMMEEt5UG9zdCBUZXN0IFJvb3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtlE+NZCD6sgVtTE8RaoE3oGdA
7PdKk1OpTHaMjN9hj1nlm0rFOjNBKRq48MYQbzi5QHzgzy/VuKS390L9i4utX8hE
dakYvS4F3ENdDb3LNgLA3mvSSabCr2PJNbsTthYnf6GVBzrGnYxN59SiY3nYLdtQ
m+0oDwva4/elRTx0yI4M6Akk860M97uDeZxTytnZJvq14PVAL34KYCNoeYUU+i9v
alcocTM6JjTDlJyeRgZsU3Y+cLl2sx4wFoc5rH6ok581Rm37/bvlvNYC4N82tVko
KzDwyHSipeaTEcYRxLKQfi2/X5C8c4Mcd2GzsjwDM8Hfh/3XEhO2uJo071BPAgMB
AAGjUzBRMB0GA1UdDgQWBBTTWTf/wNeKjyQVbTbZdDMwCjEKMTAfBgNVHSMEGDAW
gBTTWTf/wNeKjyQVbTbZdDMwCjEKMTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCkmSPR7Y/4d9RKUuxW3F/2TLlR1uEcn2zM0yMT1A0ygSyrLotB
bm3deE54J75muqjmX3pvinEbgXQnBXJbQxEd59FQT4WLwx/Z8QmOTngoPDb4ltIK
meV915jy4OZ10cacW8+nfwvqWQio6FthsnhFeaDKgoMyDlsE+N0B/2otVEj1EoMn
sGglkJS284GvUQ02LOXRs6TrkEDN/+wUDYl4jVpm3t7duU8QIUszAwL29rrJ8+9L
y1eTZAqlCP50cqQQB6HTmT1HLMJEcbjNBQBvHUejkoM7LkBxn+daogBI292y0cLa
1dQqCxWXJpQAkR5cRvU2CFesGYDw7KmQTtWo
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
    fun pinsForChain_pinsTheLeafAndNothingElse() {
        val leaf = certificateOf(LEAF_CERT_PEM)
        val intermediate = certificateOf(INTERMEDIATE_CERT_PEM)
        val root = certificateOf(ROOT_CERT_PEM)

        val pins = SpkiPinner.pinsForChain(listOf(leaf, intermediate, root))

        assertEquals(setOf(SpkiPinner.pinFor(leaf)), pins)
    }

    /** THE FINDING. `CertificatePinner` passes when ANY chain member matches ANY configured pin,
     *  so pinning an issuer admits every certificate that issuer signs. For the ordinary
     *  deployment — a self-hosted relay behind a public CA — that made the pin assert "issued by
     *  Let's Encrypt" and nothing more, which anyone who can answer for the host can satisfy in
     *  ninety seconds for free. The old test could not catch this: it passed the intermediate
     *  FIRST in the list, where it is indistinguishable from a leaf. */
    @Test
    fun pinsForChain_refusesToPinAnIssuer() {
        val leaf = certificateOf(LEAF_CERT_PEM)
        val intermediate = certificateOf(INTERMEDIATE_CERT_PEM)
        val root = certificateOf(ROOT_CERT_PEM)

        val pins = SpkiPinner.pinsForChain(listOf(leaf, intermediate, root))

        assertFalse("an intermediate must NOT be pinned", SpkiPinner.pinFor(intermediate) in pins)
        assertFalse("a trust anchor must NOT be pinned", SpkiPinner.pinFor(root) in pins)
        // And the intermediate really is one, so the assertion above is not vacuous.
        assertFalse("the fixture's intermediate is genuinely not self-issued", SpkiPinner.isTrustAnchor(intermediate))
        assertTrue("the fixture's root is genuinely self-issued", SpkiPinner.isTrustAnchor(root))
    }

    @Test
    fun rollingPins_keepsTheFreshestAndCapsTheWindow() {
        val fresh = setOf("sha256/A")
        val history = setOf("sha256/B", "sha256/C")

        val rolled = SpkiPinner.rollingPins(fresh, history)

        // Newest first and truncation from the back: the pin in use must survive the cap.
        assertEquals(listOf("sha256/A", "sha256/B"), rolled.toList())
        assertEquals(SpkiPinner.MAX_PINNED_LEAVES, rolled.size)
    }

    @Test
    fun rollingPins_doesNotGrowWhenNothingRotated() {
        val rolled = SpkiPinner.rollingPins(setOf("sha256/A"), setOf("sha256/A"))

        assertEquals(setOf("sha256/A"), rolled)
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
