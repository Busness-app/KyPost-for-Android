package org.kysecurity.mail.security

import okhttp3.CertificatePinner
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/** TOFU: the server cert pin is captured at pairing time and enforced on every later connect. */
object SpkiPinner {
    fun pinFor(certificate: Certificate): String = CertificatePinner.pin(certificate)

    /** The pins to store for an observed handshake chain: everything except the trust anchor.
     *
     *  Two mistakes are being avoided at once, and they pull in opposite directions.
     *
     *  Pinning the LEAF ALONE made every routine certificate renewal a hard outage, because a
     *  renewal mints a new leaf key that no stored pin matches, and the only way out was unpairing
     *  — which deletes the mailbox. Intermediates are pinned so a renewed leaf under an
     *  already-pinned issuer still validates.
     *
     *  Pinning the ROOT is worse than not pinning. `CertificatePinner` passes when ANY chain
     *  member matches ANY configured pin, so a pinned public root admits every certificate that
     *  root has ever issued or ever will: an attacker who can answer for the host obtains their
     *  own certificate from the same CA and the pin passes. That is not a pin.
     *
     *  Self-issued is the test, NOT `dropLast(1)`: servers commonly do not send the root, and
     *  dropping the last element blind would throw away the intermediate on exactly those chains.
     *  A chain that is entirely self-issued is a single self-signed server certificate — the
     *  self-hosted-relay case — and pinning that leaf is both correct and the only option. */
    fun pinsForChain(chain: List<Certificate>): Set<String> =
        chain.filterNot(::isTrustAnchor).ifEmpty { chain }.mapTo(LinkedHashSet(), ::pinFor)

    /** A root is self-issued. Position in the chain is presentation; this is the property. */
    internal fun isTrustAnchor(certificate: Certificate): Boolean =
        (certificate as? X509Certificate)?.let { it.issuerX500Principal == it.subjectX500Principal } == true
}
