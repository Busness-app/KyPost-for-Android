package org.kysecurity.mail.security

import okhttp3.CertificatePinner
import java.security.cert.Certificate

/** TOFU: the server cert pin is captured at pairing time and enforced on every later connect. */
object SpkiPinner {
    fun pinFor(certificate: Certificate): String = CertificatePinner.pin(certificate)
}
