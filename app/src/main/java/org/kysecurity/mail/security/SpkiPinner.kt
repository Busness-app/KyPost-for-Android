package org.kysecurity.mail.security

import okhttp3.CertificatePinner
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/** TOFU: the server cert pin is captured at pairing time and enforced on every later connect. */
object SpkiPinner {

    /** How many leaf pins may be accepted at once. Two: the one in use, and the one it replaced.
     *
     *  This is the renewal window. [org.kysecurity.mail.push.PushSyncCoordinator.refreshTlsPin]
     *  rolls a fresh leaf in on every registration that ALREADY validated against a stored pin, so
     *  a certificate rotation between two resyncs is carried rather than fatal. Larger would just
     *  widen the set of keys a stolen one hides in. */
    const val MAX_PINNED_LEAVES = 2

    fun pinFor(certificate: Certificate): String = CertificatePinner.pin(certificate)

    /** The pin to store for an observed handshake chain: THE LEAF, and nothing else.
     *
     *  `CertificatePinner` passes when ANY chain member matches ANY configured pin. That single
     *  fact rules out every issuer in the chain, not just the root:
     *
     *  - A pinned public ROOT admits every certificate that root has ever issued or ever will.
     *  - A pinned public INTERMEDIATE is the same defect one link down, and it is the one this
     *    function used to have. For the ordinary deployment — a self-hosted relay behind Let's
     *    Encrypt — pinning R11 or E5 meant the pin asserted "issued by Let's Encrypt" and nothing
     *    more. Anyone who can answer for the host (DNS hijack, BGP, a hostile resolver, a
     *    compromised registrar) obtains their own certificate from the same CA in ninety seconds,
     *    for free, and it chains to the pinned intermediate. That is not a pin; it is WebPKI with
     *    extra steps and a UI that claims otherwise.
     *  - A pinned LEAF is a pin. It names one key.
     *
     *  Leaf-only was tried before and reverted because a renewal that mints a new key matches no
     *  stored pin, and the only recovery was unpairing, which deletes the mailbox. That is a real
     *  problem and it is NOT solved by weakening the pin. It is solved by continuity —
     *  [MAX_PINNED_LEAVES] and `refreshTlsPin` — which keeps the pin current across renewals
     *  without ever accepting a key this device has not seen on an already-validated connection.
     *
     *  An entirely self-issued chain is a single self-signed server certificate, the
     *  self-hosted-relay case, and its leaf is also its anchor: pinning it is both correct and the
     *  only option, which falls out of taking the leaf without a special case. */
    fun pinsForChain(chain: List<Certificate>): Set<String> =
        chain.firstOrNull()?.let { setOf(pinFor(it)) }.orEmpty()

    /** A root is self-issued. Position in the chain is presentation; this is the property. */
    internal fun isTrustAnchor(certificate: Certificate): Boolean =
        (certificate as? X509Certificate)?.let { it.issuerX500Principal == it.subjectX500Principal } == true

    /** [fresh] first, then as much of [history] as the window allows.
     *
     *  Order is the policy: the newest observation is the one that must survive truncation. Both
     *  entries are leaves this device saw on a connection that had already validated against a pin
     *  it held, so widening to two never admits a key from outside that chain of custody. */
    fun rollingPins(fresh: Set<String>, history: Set<String>): Set<String> =
        (fresh + history).take(MAX_PINNED_LEAVES).toSet()
}
