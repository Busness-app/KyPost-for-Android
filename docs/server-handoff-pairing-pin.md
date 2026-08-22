# Server handoff: publish a leaf SPKI pin in the pairing link

**For:** kypost-server
**Client side:** done and merged-ready in kypost-android. Inert until the server does this.

## Why

The pairing request is the one call that carries `pairingToken`, the FCM/UnifiedPush endpoint and
the WebPush keys — and until now it went out inside the TOFU window, unpinned. The certificate was
only trusted *after* those secrets had already been disclosed. On a network with a locally trusted
CA (enterprise MDM, a user-installed root, a hostile captive portal), an interceptor reads the
pairing token, registers its own device against the relay first, and hands back credentials it
controls. The app then pins the attacker's certificate.

TLS hostname validation does not help here. That is exactly the case pinning is for.

The client now accepts an optional `pin` parameter in the pairing link and, when present, pins the
registration request to that one leaf key *before* sending anything. **The server has to publish
it.** Until it does, every pairing still uses TOFU.

## What to change

Add a `pin` query parameter to the `kypost://native-pair?...` URI the relay generates — both the
QR code payload and the deep link. They are the same string; the client scans the QR raw and feeds
it to the same parser.

```
kypost://native-pair?sub=<subscriber>&srv=<https url>&reg=<https url>&pt=<token>&pin=<encoded pin>
```

Everything else is unchanged. `pin` is optional; omitting it keeps today's TOFU behaviour.

## The pin value

Base64 of the SHA-256 of the **leaf** certificate's SubjectPublicKeyInfo — OkHttp's
`CertificatePinner.pin()` format. The `sha256/` prefix is optional; the client normalises both.

The leaf, not an issuer. Pinning an intermediate on a Let's Encrypt deployment asserts only
"issued by Let's Encrypt", which anyone who can answer for the host obtains for free in ninety
seconds. See the reasoning already written up in `SpkiPinner.pinsForChain`.

Compute it from the relay's serving certificate:

```sh
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Or straight off the live listener:

```sh
openssl s_client -connect relay.example.com:443 -servername relay.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Verified: that pipeline produces byte-identical output to `CertificatePinner.pin()` on the same
certificate. Checked against a generated leaf, both sides returning
`sha256/A/8Tbwpsi7a5kM1oSL0mge8ce7V1tL+orlCtOCDaDWw=`.

Read it at link-generation time from the certificate the relay is actually serving. Do not
hardcode it — see renewal below.

## ⚠ Percent-encode the value

This is the one thing that will bite you.

Base64 uses `+`, `/` and `=`. In a query string a bare `+` decodes to a **space**, so an unencoded
pin arrives corrupted. `/` and `=` happen to survive, which makes this look like it works right up
until you get a pin containing a `+` — roughly half of them.

| Emitted | Client sees |
|---|---|
| `pin=A/8Tbw...tL+orl...DaDWw=` | `A/8Tbw...tL orl...DaDWw=` → **rejected** |
| `pin=A%2F8Tbw...tL%2Borl...DaDWw%3D` | correct |

Percent-encode the whole value with a standard URI query-component encoder. Do not hand-roll it,
and do not rely on `/` and `=` surviving.

The client fails **closed** on a malformed pin: it refuses the pairing with "Certificate pin is not
a base64 SHA-256 SPKI hash" rather than silently falling back to TOFU. So an encoding bug shows up
as a broken pairing, not as a silently unpinned one. That is deliberate — dropping an unparseable
pin would reopen the exact window this parameter exists to close.

## Certificate renewal

The pin names one key. A renewal that mints a **new key** invalidates it.

- The link is generated fresh each time, so read the pin from the live certificate at generation
  time and renewals are handled for free for *new* pairings.
- Already-paired devices are unaffected by this parameter — they use the pin captured from their
  own successful handshake, and the existing re-trust ceremony
  (`PushHomeViewModel.reconnectToServer`) is unchanged.
- If your ACME client reuses the key across renewals the pin is stable; if it rotates (the safer
  default) the pin changes each renewal. Either is fine as long as the link is generated from the
  live cert.

## What the client does with it

For reference, so the two halves stay in sync:

1. `NativePairingDeepLinkParser` parses `pin`, normalises it to `sha256/<base64>`, rejects
   anything that is not a base64 SHA-256, and puts it on `PairingData.spkiPin`.
2. `NativeRegistrationClient.register` tags the registration request with `LinkPin(host, pin)`.
   The host is the `reg` URL's host, since that is the certificate the handshake is against.
3. `PinnedOrFallbackCallFactory` honours that tag **only** in the `NeverPaired` branch, replacing
   the unpinned TOFU fallback with a client pinned to that one key. `TlsPinState.Lost` still fails
   closed — a link cannot re-authorise a server whose stored pin has gone missing.
4. `spkiPin` is not persisted. Once registration succeeds the pin captured from the (now verified)
   handshake supersedes it.

## Scope — be honest about this in any docs

This closes the hostile-**network** hole. It does **not** close a hostile **link**: whoever writes
the link can simply omit `pin` and put the client back in the TOFU window. The link itself is the
out-of-band trust anchor — it is trusted because the user reads it off their own relay's admin UI.

If you want to defend a hostile link too, that is a different mechanism: sign the pairing document
with an identity key the app already trusts, or show the user a fingerprint confirmation screen
after first pairing so they can compare out-of-band. Neither is implemented. The client-side half
of the fingerprint screen was offered and deferred.

## How to test it

Client-side fixtures already exist and pass — use them as the contract:

- `NativePairingDeepLinkParserTest.aRealPercentEncodedPin_survivesTheRoundTrip` — a real
  `CertificatePinner.pin()` value containing both `+` and `/`, correctly encoded. **Generate a link
  from the relay and check it parses to the same shape.**
- `NativePairingDeepLinkParserTest.anUnencodedPlusInThePin_isRefusedRatherThanMangledIntoATofuPairing`
  — the exact failure an unencoded pin produces.
- `SpkiPinNormalizationTest` — what the client accepts and rejects.
- `NativeRegistrationClientTest.aLinkPinIsTaggedOntoTheRegistrationRequest`
- `PinnedOrFallbackCallFactoryTest.aLinkPinReplacesTheUnpinnedFallbackBeforeTheFirstPairing`
- `PinnedOrFallbackCallFactoryTest.aLinkPinDoesNotRescueALostPin`

End-to-end check worth doing once on the server side: generate a pairing link, pair a device
through a proxy with a user-installed CA. Before this change the pairing succeeds and the app pins
the proxy. After it, with `pin` published, the registration call must fail the TLS handshake.

## Checklist

- [ ] Read the leaf SPKI pin from the live serving certificate at link-generation time
- [ ] Percent-encode it into the `pin` query parameter
- [ ] Emit it in both the QR payload and the deep link (same string)
- [ ] Verify a generated link parses with the client's fixtures above
- [ ] Confirm a hostile-CA proxy now fails the registration handshake
- [ ] Document that `pin` is optional and its absence means TOFU
