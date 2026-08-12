package org.kysecurity.mail.security

import okhttp3.CertificatePinner
import java.security.cert.Certificate

/**
 * TOFU (trust-on-first-use) certificate pinning support — see "Certificate pinning" in the
 * 2026-07-22 security-hardening spec. kypost is self-hosted with a per-user server URL, so there
 * is no fixed certificate to hardcode; instead the server's certificate pin is captured once at
 * pairing time and enforced on every later connection. This wraps OkHttp's own
 * [CertificatePinner.pin] (which already computes the correct `sha256/BASE64` SPKI hash) purely
 * to give the operation a name specific to this feature, not because the computation itself
 * needs reimplementing.
 */
object SpkiPinner {
    fun pinFor(certificate: Certificate): String = CertificatePinner.pin(certificate)
}
