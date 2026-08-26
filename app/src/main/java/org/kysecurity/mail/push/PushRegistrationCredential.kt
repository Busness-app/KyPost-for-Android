package org.kysecurity.mail.push

/** What this build registers for push with: the token, the transport that token belongs to, and
 *  the RFC 8291 keys when that transport carries encrypted payloads.
 *
 *  Pairing used to send a bare token and leave `transport` unset, which the server resolves by
 *  deriving one from `platform` — `"fcm"` for anything that is not iOS
 *  (`normalizeNativeTransport`, server-side). That is correct for a Firebase build and wrong
 *  for one without it, in two ways at once: the server relays to a token that can never receive,
 *  and it stores no WebPush keys, so payloads stay in the clear on a public broker and the device
 *  is refused MFA challenges. Naming the transport at pairing is what makes a Firebase-free
 *  channel possible at all.
 *
 *  [p256dh] and [auth] are meaningful only for `unifiedpush`; the server ignores them on any
 *  other transport and refuses a half-supplied pair. */
data class PushRegistrationCredential(
    val token: String,
    /** Null means "let the server derive it", which is what the Firebase builds want. */
    val transport: PushTransport? = null,
    val p256dh: String? = null,
    val auth: String? = null,
) {
    /** Redacted: [token] is a delivery capability and [auth] lets a holder forge a notification
     *  this device would accept. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "PushRegistrationCredential(redacted)"
}
