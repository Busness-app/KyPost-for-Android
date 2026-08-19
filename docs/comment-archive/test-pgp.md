# Comment archive - test/pgp

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCeremonyExitTest.kt

### `class EnrollmentCeremonyExitTest`

```
/**
 * The tail of the ceremony, and the exit table.
 *
 * A real envelope is built here rather than mocked, because the seam being tested is exactly the one
 * between the state machine and the pure crypto in `DeviceEnvelope.kt`: a ceremony that assembled the
 * AAD or the HKDF salt wrongly would still "work" against a stubbed opener.
 */
```

### `fun theSealerReceivesTheOpenedPlaintext()`

```
    /** The sealer receives what the browser sealed, byte for byte. Anything else means the AAD, the
     *  HKDF salt or the parse is wrong, and the user would see the substituted-key alarm. */
```

### `fun thePlaintextIsZeroedInPlaceAfterSealing()`

```
    /**
     * The plaintext is the account's PGP private key. Its lifetime is the real exposure, and it does
     * NOT go into `EnrollmentSession` — that holder has no consumer until the deferred decryption
     * work lands, and populating it for zero readers is exposure bought for nothing.
     */
```

### `fun aFailedReportStillMeansEnrolledAndEnqueuesTheWorker()`

```
    /**
     * **A failed report still means enrolled.** The local seal is real; only the server's marker is
     * stale, and the durable worker already exists to correct it. Reporting this as a failure would
     * make the user re-run a ceremony whose expensive half already succeeded.
     */
```

### `fun anEnvelopeSealedForAnotherDeviceIsCouldNotOpen()`

```
    /**
     * **A failed GCM open is never a retry.** The AAD binds device and identity, so a failure means
     * the envelope was sealed for another device or under an identity the account no longer
     * advertises. Here the envelope was sealed for a different device id.
     */
```

### `fun anEnvelopeSealedUnderAnotherIdentityIsCouldNotOpen()`

```
    /** The other half of the AAD binding: an envelope minted under a fingerprint this account no
     *  longer advertises. Same verdict, same copy — the phone cannot tell the two apart, and the
     *  copy must not claim it can. */
```

### `fun anEcdhFailureIsCouldNotOpenAndDestroysTheKeypairWithNoSecondAttempt()`

```
    /** The ECDH itself can fail — a malformed peer point that got past the parse, or a key the
     *  Keystore will no longer agree with. Indistinguishable from a hostile envelope from here, and
     *  treated the same: no retry. */
```

### `fun losingTheLockScreenBeforeTheSealIsItsOwnReason()`

```
    /** The lock screen can be removed between the gate and the seal. `EnrollmentVault.ensureKey()`
     *  reports it, and the ceremony must not present it as a mysterious failure. */
```

### `fun aCancelledBiometricReturnsToTheCodeWithThePlaintextZeroed()`

```
    /**
     * A cancel is not a failure. The envelope is still on the relay, so the user gets the code back
     * and a way to try again — and the plaintext does not survive the round trip.
     *
     * The window ends rather than re-prompting three seconds later; see deviation 8 in this plan.
     *
     * Also binds [EnrollmentCeremony.isIdle] to the window rather than to the state alone: `run()`'s
     * `finally` sets it back to `true` on every path including a throw, so asserting it only after
     * `run()` returns is true by construction and cannot fail. Reading it from *inside* `onState` —
     * the moment the window's `ShowingCode` is emitted, before the cancel — is what actually exercises
     * the `isIdle = false` at the top of `run()`.
     */
```

### `fun teardownDestroysALiveKeypairAndIsIdempotent()`

```
    /** Leaving the screen is the restart path, and it must take the key with it. */
```

### `fun teardownAfterABlockedGateDestroysNothing()`

```
    /** A ceremony blocked at the gate never minted anything, so teardown must not claim a deletion
     *  it did not perform — `EnrollmentTeardown` feeds that boolean to a `SecurityWipe.step`. */
```

### `private enum class Cleanup`

```
    /**
     * **The exit table, made structural.**
     *
     * The `when` below is exhaustive over [EnrollmentUiState] with no `else`, so adding a state
     * without deciding its cleanup is a **compile error**, not a silently untested path. That is the
     * point: an exit added later without cleanup is exactly the defect this ceremony cannot afford.
     */
```

### `fun successDropsThePlaintextTheServerHadDecrypted()`

```
    /**
     * Enrolling is the moment this device stops depending on the server being able to read the
     * account's mail. Anything cached before it that the server decrypted is plaintext the new threat
     * model does not account for: the server can no longer produce it, and nothing else on the device
     * removes it until the next full snapshot up to 24 hours later — the delta path deliberately
     * preserves bodies, so deltas never clear it.
     */
```

### `fun thePlaintextIsDroppedEvenWhenTheServerCannotBeTold()`

```
    /**
     * Cleared before [EnrollmentTransport.reportEnrolled], which is a network round trip that can run
     * to a full timeout or fail outright. A local privacy action must not be queued behind it.
     */
```

### `fun aFailedCeremonyLeavesTheCacheAlone()`

```
    /** A ceremony that never sealed has not changed where the account's key lives, so there is no
     *  reason to drop mail the user can still read. */
```

### `fun aKeystoreThatCannotMintFailsWithNoDeviceKey()`

```
    /**
     * [FailureReason.NO_DEVICE_KEY] has four production call sites and, until these, no test at any
     * of them — it was unreachable because [FakePorts] hardcoded a minting keystore with no way to
     * make an accessor fail. An untested failure branch on the path that mints and publishes a key is
     * the branch most likely to be silently rewired, so each site gets its own case.
     *
     * Every one of them must also destroy the keypair. `keyPairLive` is set *before* the mint is
     * checked precisely because a failed `newKeyPair()` can still leave a half-generated key behind,
     * and a key that outlives a ceremony is a standing unauthenticated path to every envelope the
     * relay retains.
     */
```

### `fun aKeyWhosePublicHalfCannotBeReadFailsWithNoDeviceKey()`

```
    /** The key minted, but its public half cannot be read back — so there is nothing to publish. */
```

### `fun aKeyDestroyedMidWindowFailsWithNoDeviceKey()`

```
    /**
     * The key is destroyed under a running window — `SecurityWipe` and Hostile Location Protection
     * both do exactly this to a live screen. The next bucket boundary must fail the ceremony rather
     * than derive a code from a key that no longer exists.
     */
```

### `fun aKeyDestroyedBeforeTheOpenFailsWithNoDeviceKey()`

```
    /**
     * The key survives long enough to receive an envelope and then goes. The open needs the keystore
     * point as the HKDF salt, so this must fail rather than derive a key from a substitute.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCeremonyCodeTest.kt

### `class EnrollmentCeremonyCodeTest`

```
/**
 * The published key, the displayed code, and the polling window.
 *
 * Every assertion here distinguishes a correct implementation from a plausible wrong one. Audit
 * run-6 found the previous plan's Task 7 asserting `WorkInfo.progress`, which is empty for every
 * worker ever enqueued — it would have passed against a credential leak.
 */
```

### `fun theCodeDerivesFromTheKeystoreKeyAndNotFromWhatWasPublished()`

```
    /**
     * **The one security property the device half owns.**
     *
     * The browser derives its code from the key the *server* handed it and refuses to seal unless
     * the two match. If this device ever derived from a server-supplied value — or from a cached
     * copy of what it published — the comparison would compare the server against itself and the
     * whole control would be decoration.
     *
     * [FakeEnrollmentKeys] returns a different point from `rawPublicKey()` than the one
     * `encodedPublicKey()` base64s, so "derived from the keystore" and "derived from what was
     * published" are different strings. That is what makes this test able to fail.
     */
```

### `fun theKeyIsPublishedOnEveryCeremonyNotOnce()`

```
    /**
     * Any write to the account's PGP identity clears the stored key server-side, so a device that
     * published only at pairing fails silently after a rotation — the user sees a code, types it,
     * and nothing ever arrives.
     */
```

### `fun theCodeRecomputesOnTheBucketBoundaryAndNotBefore()`

```
    /**
     * Three buckets are crossed in a five-minute window (0s, 120s, 240s), so exactly three codes are
     * shown. Fewer means the code went stale on screen while the browser had moved on; more means it
     * is being recomputed off the boundary, and the user is re-reading a code for no reason.
     */
```

### `fun pollingStopsAtTheDeadline()`

```
    /**
     * The window is bounded, and the bound is not cosmetic: the screen holds a published enrollment
     * key and a code the user is reading aloud, and spec 1 requires `deleteKeyPair()` on the exits of
     * a ceremony — so there has to *be* a defined exit rather than a loop that runs until the process
     * dies.
     *
     * 300 seconds at 3-second intervals is exactly 100 attempts.
     */
```

### `fun aResumedWindowShowsACodeBeforeItPolls()`

```
    /**
     * A resumed window must put a code back on screen **before it does anything else.**
     *
     * `shownBucket` is instance state that survives the loop, so a window reopened in the same bucket
     * it closed in finds it unchanged and emits nothing. The screen then stays on `WaitingTimedOut` —
     * "Nothing has arrived in the last five minutes" — while a window runs silently behind it, and
     * the state that says the ceremony is *waiting on the browser* never appears. `poll()` resets
     * `shownBucket` on entry to prevent it.
     *
     * The two existing tests cannot catch a missing reset and both pass without it:
     * `theCodeRecomputesOnTheBucketBoundaryAndNotBefore` sees the same emissions either way because
     * the first window already starts at `Long.MIN_VALUE`, and
     * `checkAgainOpensAFreshWindowAgainstTheSameKeypair` derives its expected bucket *from the
     * emission it receives*, so it cannot notice one that never arrived.
     *
     * The envelope is made to arrive on the resumed window's FIRST fetch. That is what makes this
     * decisive rather than merely slow: with the reset the next state is `ShowingCode`, without it
     * the ceremony goes straight to `Opening` and no code is ever re-shown.
     */
```

### `fun aResumedWindowShowsACodeBeforeItPolls() - body`

```
        // Same bucket the window closed in: the clock is not advanced here on purpose. A test that
        // advanced it would cross a boundary, the bucket would differ, and the emission would happen
        // with or without the reset — which is exactly how this fix came to have no test.
```

### `fun checkAgainOpensAFreshWindowAgainstTheSameKeypair()`

```
    /**
     * **"Check again" resumes; it does not restart.**
     *
     * A restart would rotate the key, which would invalidate the code the user may have already
     * typed into the browser. Leaving the screen and re-entering is the restart, and that path does
     * rotate.
     */
```

### `fun checkAgainOpensAFreshWindowAgainstTheSameKeypair() - body`

```
        // The code itself still rotates with the 120-second bucket — that is not a restart, and
        // the browser accepts the current bucket. What must not change is the key BEHIND it, so
        // the assertion is that the resumed code is still derivable from the same keystore point.
```

### `fun aTransientFailureOrRateLimitKeepsWaiting()`

```
    /** A transient network failure or a 429 mid-window is not a reason to tear down a ceremony the
     *  user is halfway through typing. */
```

### `fun aTransientFailureOrRateLimitKeepsWaiting() - body`

```
        // Up to the point the envelope arrives. What happens to a `{}` envelope afterwards is
        // Task 5's business, and this test must not start asserting it.
```

### `fun a401WhilePollingFailsAndDestroysTheKeypair()`

```
    /** A credential the server refuses will not start working, and the ceremony holds a published
     *  key that must not be left behind. */
```

## app/src/test/java/org/kysecurity/mail/pgp/SignerBindingTest.kt

### `class SignerBindingTest`

```
/**
 * The three assertions that matter most are [autocryptKeyIsNeverConfirmed],
 * [changedKeyIsNeverJustUnknown], and [aSignatureFromAnotherContactsKeyIsNeverAttributedToThisSender].
 * All three are cases where the wrong answer is *plausible* and quiet: the first over-claims
 * identity on a key nobody checked, the second displays an active-attack signal as the most routine
 * message in the app, and the third lets any contact in the address book forge another contact's
 * `From` header and have their own signature attributed to the person they impersonated.
 */
```

### `private val testKeyId`

```
    // Deriving it rather than inventing a number keeps every fixture that claims "signed by this
    // key" honest against what the key material actually contains.
```

### `fun aServerSuppliedVerifiedFlagCannotConfirmASigner()`

```
        // THE headline change. `SignerKey.verified` arrives in the same JSON body as the
        // ciphertext, so a hostile relay setting it to true used to render "✅ signature confirmed"
        // over a key it chose, beside a sender it also chose. The server's keys are still worth a
        // continuity claim — that is what makes a first-contact message say anything — but the
        // verdict is capped, and `verified` is not read at all.
```

### `fun aLocalKeyOverridesEveryServerClaim()`

```
        // The relay offers its own key, marked verified, and signs with it. This device holds a
        // DIFFERENT key for the sender. Whatever the relay says, the message was not signed with
        // the key we hold — and saying so is the entire point of resolving locally first.
```

### `fun aConflictOutranksAnOtherwiseGoodKeyForTheSameSender()`

```
        // A conflict outranks a good key for the same sender. Two entries for one address means
        // one of them is a key that changed, and reporting the survivor as verified would hide
        // precisely the event worth reporting.
```

### `fun aSignatureFromAnotherContactsKeyIsNeverAttributedToThisSender()`

```
        // Eve is an ordinary contact in the address book — her key harvested like anyone else's.
        // She forges `From: bob@example.com` and signs with her OWN key. decrypt() resolves the
        // one-pass signature against the whole offered, non-conflicted key set and reports
        // valid = true — it verifies, just not against Bob's key. Attributing that to Bob because
        // *a* key is bound to Bob's address is exactly the bug this check exists to close.
```

### `fun aSignatureMatchingTheSendersBoundKeyIdIsStillVerified()`

```
        // The happy path must not regress: a signature genuinely made by the sender's own bound
        // key still verifies, both unconfirmed (VERIFIED_SEEN_BEFORE) and confirmed
        // (VERIFIED_CONFIRMED).
```

### `fun anUnparseableBoundKeyGrantsNoPass()`

```
        // A bound key that will not parse must never be treated as a match just because *some*
        // key is bound to the sender — signerKeyIdsOf returns empty rather than throwing, and an
        // empty set can never contain signature.signerKeyId.
```

### `section banner before verifiedIsReadFromTheKeyThatActuallySignedNotAnyBoundKey()`

```
    // --- Finding 2: `verified` must come from the key that signed, not any key bound to the address. ---

```

### `fun verifiedIsReadFromTheKeyThatActuallySignedNotAnyBoundKey()`

```
        // Two keys can share an address whenever two contacts list it — contact address lists are
        // attacker-influenceable (pgp_qr_bind_confirm_body warns exactly this). Here bob@example.com
        // has TWO non-conflicted bound keys: one confirmed (manual) that did NOT sign this message,
        // and one Autocrypt-harvested key that DID. The verdict must reflect the key that actually
        // produced the signature, not "some bound key for this address is confirmed."
```

### `section banner before anEncryptionOnlySubkeyIsNotASigner()`

```
    // --- Finding 3: the subkey path, uncovered before this test. ---

```

### `fun anEncryptionOnlySubkeyIsNotASigner()`

```
        // This test used to assert the OPPOSITE, and said so: it pinned that signerKeyIdsOf
        // "accepts a subkey's id regardless of usage flags, exactly the looseness recorded in that
        // function's KDoc", and noted that "a signature could not really be produced with this
        // specific key in practice".
        //
        // That looseness is now closed. TestPgpPrivateKey.ARMORED_PUBLIC's subkey
        // (204EA3568BC889DD, algo 18/ECDH) is ENCRYPTION-only per `gpg --list-packets` (key flags
        // 0C), so a signature claiming to come from it is not a signature from this identity, and
        // the id no longer matches anything.
```

### `fun anUnboundSubkeyGraftedOntoAGenuineKeyIsNotASigner()`

```
        // The grafting attack. BouncyCastle's PGPPublicKeyRing constructor stores subkeys without
        // verifying their binding signatures, so an attacker who supplies the armored blob — which
        // on the client-protected read path the relay does — could append a subkey of their own to
        // a genuine contact's key and have signatures by it attributed to that contact.
        //
        // Built by splicing the subkey packets of one real key onto another real key's primary, so
        // the binding signature present is over the WRONG primary and cannot verify.
```

### `fun theClientHoldsNoSenderParserOfItsOwn()`

```
        // signatureStateFor takes no sender argument at all — the property the deletion actually
        // established, and one noKeysIsUnknown cannot show (an empty signerKeys list can't prove
        // anything about a field that IS present). This pins the other half: SignerKey.addresses
        // is carried straight through from the server's binding and is never read here, even
        // though the field still exists on the data class and still holds attacker-influenceable
        // content. A key bound to a nonsense, unparseable "address" must verify exactly as if its
        // address were sane, because nothing in this function ever looks at it. If someone
        // reintroduces a From-header parser or an address comparison, either this fails to
        // compile (no sender to compare against) or this assertion starts failing (addresses
        // suddenly matter). See the KDoc on signatureStateFor for the 27-divergence harness that
        // made this a rule.
```

### `private fun graftSubkeysOf(...)`

```
    /**
     * A key ring made of [onto]'s primary key plus [armoredPublicKey]'s subkeys.
     *
     * `PGPPublicKeyRing.insertPublicKey` is what an attacker's own tooling would do: it appends the
     * subkey and its existing binding signature verbatim, and BouncyCastle stores both without ever
     * checking that the signature is over THIS primary. The resulting blob parses cleanly.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EncryptedMessageReaderTest.kt

### `fun theSignatureVerdictComesFromTheBoundKeyNotTheMessage()`

```
        // The message signs itself with a key we hold no binding for. That is SIGNER_UNKNOWN,
        // never VERIFIED_* — a message that vouches for itself proves only that whoever wrote
        // it owned a key.
```

### `fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender()`

```
        // The regression this exists for: if the reader does not hand the bound keys to
        // PgpDecryptor, `valid` stays false, and signatureStateFor maps signed + bound + invalid
        // to INVALID — telling the user that every legitimately signed message from a
        // correspondent they DO hold a key for is an impersonation.
```

### `fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender() - publicKey fixture`

```
            // NOT ARMORED_PRIVATE: PGPPublicKeyRingCollection (what both PgpDecryptor's one-pass
            // verification and signerKeyIdsOf parse the offered key with) rejects a secret-key
            // block outright — "PGPSecretKeyRing found where PGPPublicKeyRing expected" — so an
            // armored private key can never stand in for a published public key here. ARMORED_PUBLIC
            // is the same key pair's public half, exported separately by gpg, exactly the shape a
            // real caller holds (see PgpDecryptorTest and TestPgpPrivateKey's own KDoc).
```

### `fun aKeyBoundToADifferentSenderIsNeverOfferedToTheSignatureCheck()`

```
        // The forgery case, at the reader level. An ordinary contact signs a message and forges
        // the From header to name someone else. If the reader offered the whole address book, the
        // signature would verify against the forger's own key and be attributed to the person
        // named in From. Only keys the SERVER actually bound to the resolved sender may appear in
        // payload.signerKeys at all — the reader itself does no address matching (see
        // SignerBinding.signatureStateFor's KDoc and SignerBindingTest.theClientHoldsNoSenderParserOfItsOwn:
        // `.addresses` is carried straight through and never read past the server's own narrowing).
        // So the fixture that proves "never offered" has to use physically different key material
        // from the one that actually produced ARMORED_MESSAGE's signature — TestPgpKey.ARMORED,
        // a real, parseable, but unrelated key — rather than reusing ARMORED_PUBLIC, which IS the
        // signer's key regardless of which address a SignerKey entry claims it is bound to. Offering
        // it would spuriously verify no matter what `.addresses` says, which is exactly the false
        // positive this test exists to catch.
```

### `fun aConflictedKeyYieldsKeyChanged()`

```
        // Named for what this actually proves, not for the offeredKeys filter in
        // EncryptedMessageReader: signatureStateFor returns KEY_CHANGED the moment ANY entry in
        // signerKeys has conflict = true, before it ever looks at which key was offered to
        // PgpDecryptor or whether the signature matched. That precedence means this test cannot
        // observe — and must not claim to prove — that the conflicted key's material was kept out
        // of the crypto layer. See the KDoc on the `offeredKeys` filter in
        // EncryptedMessageReader.kt for why the filter still stays despite being unobservable here.
```

### `section banner before the detached-signature tests`

```
    // --- The detached-signature branch (payload.encryptedPayload.isBlank()): a signed-but-not-
    // encrypted message. successPayload() always sets a non-blank encryptedPayload, so without
    // these this whole branch — and PgpDecryptor.verifyDetached — never runs in CI. ---
```

### `fun aDetachedSignatureFromAnUnboundKeyIsUnknownNotUnsigned()`

```
        // Pins `present = true`. With no bound keys, offeredKeys is empty, so the code falls back
        // to `verifyDetached(armoredPublicKey = "", ...)`. That relies on
        // PGPPublicKeyRingCollection returning an EMPTY collection for an empty input rather than
        // throwing — if it threw instead, verifyDetached's catch-all would report `present = false`
        // and this would come back NONE ("not signed") for a message that plainly is signed, and a
        // conflicted-key case (below) would silently lose its KEY_CHANGED warning behind the same
        // NONE. Nothing else in this suite reaches this fallback.
```

### `section banner before aClientUnprotectedAccountSaysSo()`

```
    // --- Exit-table rows the brief's fixtures never reached. ---

```

### `fun aMessageWithNoOpenPgpPayloadIsTerminalNotRetryable()`

```
        // Spec defect fix: NoPayload (404) used to collapse into FetchFailed, which the UI renders
        // with a Retry button. Retry cannot help a terminal 404 — the message simply carries no
        // OpenPGP payload — so it gets its own outcome instead.
```

### `fun aKeyThatVanishesBetweenUnsealAndFetchAsksForAnUnlockAgain()`

```
        // FakeVaultOpener.keyToHold exists as exactly this seam: open() reports Opened without
        // actually leaving a key in EnrollmentSession, simulating the app locking (lockNow() clears
        // the session) in the gap between the unseal returning and the post-unseal re-read a few
        // lines later in EncryptedMessageReader.read.
```

### `section banner before aRelaySuppliedVerifiedFlagCannotConfirmASigner()`

```
    // --- The relay is not the source of truth about who signed a message. ---

```

### `fun aRelaySuppliedVerifiedFlagCannotConfirmASigner()`

```
        // End to end through the reader, not just the verdict function: the relay hands over a key
        // for the resolved sender AND marks it verified, which is the whole of what it takes to
        // have rendered "✅ signature confirmed" before this device held an opinion of its own.
```

### `fun aLocalKeyThatDidNotSignOutranksAnyRelayClaim()`

```
        // This device holds a key for bob@example.com. The message decrypts, but it was signed by
        // some other key — and the relay is vouching for that other key as verified. The local
        // opinion wins and the user is told the key changed, rather than being shown a badge.
```

### `fun aLookupFailureDegradesToTheRelayRatherThanFailingTheRead()`

```
        // Room can throw — a wipe closed the database out from under this call, protection is on
        // and the in-memory graph is being rebuilt. Reading a message must not become impossible
        // because the trust lookup did; it degrades to the capped server-key path.
```

## app/src/test/java/org/kysecurity/mail/pgp/FakeEnrollmentPorts.kt

### `file header above FAKE_FINGERPRINT`

```
/**
 * JVM fakes for all five enrollment ports, plus a [FakePorts] bundle that wires a ceremony from
 * them. This repo has no mocking framework — see `org.kysecurity.mail.testing.FakeCalls` for the same
 * approach one layer down.
 *
 * `internal`, not `private`: Kotlin compiles a top-level `private` class to a package-level JVM
 * name, so a second file in this package declaring the same name fails to compile as a duplicate
 * class. That already cost this package four near-identical copies of one fake.
 */
```

### `internal fun sealEnvelope(...)`

```
/**
 * Seals a real envelope the fake ports can open, using the same primitives the browser does.
 *
 * Lives here rather than in one test class because the seam it exercises — the state machine against
 * the pure crypto in `DeviceEnvelope.kt` — is reached from more than one suite, and a second private
 * copy is how this package previously ended up with four near-identical versions of one fake.
 *
 * The shared secret is whatever [FakeEnrollmentKeys.sharedSecretResult] returns: the ECDH is the one
 * step a JVM test cannot perform, and it is covered on hardware by `EnrollmentKeyStoreTest`.
 */
```

### `internal class FakeEnrollmentKeys`

```
/**
 * [rawPublicKey] and [encodedPublicKey] deliberately **disagree**.
 *
 * The one security property the device half owns is that the code derives from the key in this
 * device's own keystore, never from anything the server sent back or from a cached copy of what was
 * published. A fake whose two accessors returned the same point could not tell a correct
 * implementation from one that derived the code from the value it published — both would be green.
 * Making them differ is what turns that into a test that fails when the derivation moves.
 */
```

### `var vanished`

```
    /**
     * Destroys the key from under a running ceremony, as `SecurityWipe` and Hostile Location
     * Protection both genuinely can: both tear the enrollment down on a live screen. Set from a test's
     * `onState` to reach the mid-window branch, which no list of canned results can produce.
     */
```

### `var encodingFails`

```
    /** A key that mints but whose public half cannot be read back — the Keystore entry exists while
     *  `getCertificate` returns nothing. Separate from [vanished] because it is reachable
     *  synchronously, immediately after a *successful* mint. */
```

### `internal class FakeEnrollmentClock`

```
/**
 * A clock the test drives. [sleep] does not sleep — it advances [elapsedRealtimeMs] and
 * [epochSeconds] by exactly the amount asked for, so a five-minute polling window costs a hundred
 * iterations of arithmetic rather than five minutes of wall clock.
 */
```

### `internal class FakePorts`

```
/**
 * Every port, a recorded transcript of the states the ceremony emitted, and a factory.
 *
 * One constructor with named defaults, not an overload set. Two constructors whose parameters both
 * default would be ambiguous at any call site that names only a parameter they share.
 */
```

### `FakePorts(minting = ...)`

```
    /** A keystore that refuses to mint — StrongBox and the TEE fallback both failing. Exposed here
     *  because [FailureReason.NO_DEVICE_KEY] was otherwise unreachable from any test: this bundle
     *  hardcoded a minting keystore, so the branch had production call sites and no coverage. */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpMimeWriterTest.kt

### `class PgpMimeWriterTest`

```
/**
 * [PgpMimeReader] is the oracle here, exactly as [PgpDecryptor] is for [PgpEncryptorTest].
 *
 * Using an independent parser — `angus.mail`, which this writer does not use — to validate what the
 * writer emits is strictly stronger than round-tripping through one library's own encoder and
 * decoder, which can agree on a shape no other MUA accepts.
 */
```

### `fun protectedContentParsesBackThroughPgpMimeReader()`

```
    /**
     * The real subject travels inside the ciphertext as a protected header, and the reader lifts it
     * back out. If this breaks, every KyPost-to-KyPost message displays the outer placeholder
     * ("[Encrypted] Email Sent by KyPost") instead of its actual subject.
     */
```

### `fun repeatsTheSubjectInAnRfc822HeadersPart()`

```
    /**
     * The memoryhole / draft-ietf-lamps-header-protection convention: the real Subject is repeated
     * in a `text/rfc822-headers` part so other clients can find it.
     *
     * Without this part the subject is still readable by KyPost — which reads the top-level header —
     * but Thunderbird, Mutt and K-9 show the placeholder, and the server's own
     * `ExtractProtectedSubject` is written to accept exactly this shape.
     */
```

### `fun envelopeSatisfiesTheRelayDeliveryValidator()`

```
    /**
     * Mirrors the relay's own `validatePGPMimeDeliveryShape` rule for rule.
     *
     * The server relays these bytes verbatim over SMTP and synthesizes nothing, so anything missing
     * here is simply absent from the delivered mail — and anything forbidden gets the whole send
     * rejected with a plain-text 400 after the ciphertext was already built.
     */
```

### `fun aCompleteDeliveryRoundTripsAndLeaksNothingInCleartext()`

```
    /**
     * The whole outbound path composed: protect the headers, encrypt and sign, wrap as PGP/MIME —
     * then take it apart the way a recipient does.
     *
     * The leak assertion is the point. The real subject must appear nowhere in the delivery's
     * cleartext; if the placeholder is ever dropped, every encrypted message advertises its subject
     * to anyone who can see the envelope, and no unit test of either half would notice.
     */
```

### `fun dateIsAsciiUnderANonEnglishDefaultLocale()`

```
    /**
     * The `Date` header must be ASCII whatever the device's locale.
     *
     * This passes today without any locale pinning — `RFC_1123_DATE_TIME` hardcodes the English
     * abbreviations RFC 1123 mandates, so it is already locale-independent. The test exists for the
     * refactor that replaces it with `ofPattern("EEE, dd MMM yyyy HH:mm:ss Z")`, which looks
     * equivalent, renders through the default locale, and emits "Sal, 11 Ağu 2026" on a Turkish
     * device. That is a bug that never shows up in development and always shows up for some users.
     */
```

### `fun attachmentSurvivesInsideTheProtectedContent()`

```
    /**
     * Attachments ride inside the ciphertext, decoded by an independent parser here.
     *
     * The browser client has no attachment support on this path, but this app's compose screen has
     * an attach button — so dropping them silently would send a message the user believes carried a
     * file.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/TestPgpPrivateKey.kt

### `internal object TestPgpPrivateKey`

```
/**
 * A disposable, passphrase-free ed25519/cv25519 pair and one message encrypted and signed to it,
 * both produced by `gpg` — deliberately a different OpenPGP implementation from the Bouncy Castle
 * code under test, for the reason [TestPgpKey] gives: a fixture generated by the implementation
 * being tested only proves the code agrees with itself.
 *
 * Never a real key. Regenerate with the commands in this task's plan step if it needs replacing.
 */
```

### `val ARMORED_MIME_MESSAGE`

```
    /** Decrypts to a real PGP/MIME payload — `Content-Type: text/plain` followed by
     *  [EXPECTED_PLAINTEXT] — unlike [ARMORED_MESSAGE], whose plaintext is bare text with no MIME
     *  headers and so is unparseable by [PgpMimeReader]. Same key pair, same one-pass self-signature
     *  shape, produced the same way: `gpg --sign --encrypt`, this time over a MIME-wrapped plaintext.
     *  Needed because [EncryptedMessageReaderTest] exercises the full decrypt-then-parse path, which
     *  [ARMORED_MESSAGE] cannot reach past PgpMimeReader without regenerating that shared fixture and
     *  risking every other test built on it.
```

### `const val UNPROTECTED_PLAINTEXT`

```
    /** Same key, same plaintext, but a legacy Symmetrically Encrypted Data packet (tag 9) instead
     *  of the Sym. Encrypted Integrity Protected Data packet (tag 18) `ARMORED_MESSAGE` uses —
     *  produced with `gpg --rfc2440 --disable-mdc`. A decryptor that accepts this is accepting
     *  ciphertext an attacker could tamper with undetected. */
```

## app/src/test/java/org/kysecurity/mail/pgp/TestPgpKey.kt

### `internal object TestPgpKey`

```
/** A disposable ed25519 key generated with `gpg --quick-generate-key`, purely as a test fixture.
 *  [FINGERPRINT] is gpg's own reported fingerprint for it, so tests built on this pair confirm
 *  [PgpFingerprint.compute] agrees with a real, independent OpenPGP implementation rather than just
 *  round-tripping through the same Bouncy Castle code it is built on. Shared by every test that
 *  needs a genuinely parseable armored key. */
```

## app/src/test/java/org/kysecurity/mail/pgp/TestPgpSecondKey.kt

### `internal object TestPgpSecondKey`

```
/**
 * A second disposable, passphrase-free ed25519/cv25519 pair produced by `gpg`, so multi-recipient
 * tests can prove that *each* recipient can open the message rather than just the first.
 *
 * [TestPgpKey] cannot serve this purpose: it is a signing-only EdDSA key with no encryption subkey,
 * so it is not a usable encryption recipient at all.
 *
 * Never a real key. Regenerate with:
 * `gpg --batch --passphrase "" --quick-generate-key "SecondRecipientTest <second@example.invalid>" default default 0`
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/ClientEncryptedSenderTest.kt

### `fun toAndCcShareDeliveryZeroAndEachBccGetsItsOwn()`

```
    /**
     * To and CC share one ciphertext; every BCC recipient gets their own.
     *
     * This is the whole reason `deliveries` is a list. One shared ciphertext would put each BCC
     * recipient's key id in a packet every other recipient can read — which is exactly the thing
     * BCC promises not to do.
     */
```

### `fun aBccDeliveryIsEncryptedOnlyToThatBccKey()`

```
    /**
     * A BCC recipient's delivery is encrypted to their key alone.
     *
     * Asserted by decryption, not by inspecting recipient lists: the delivery must open with the BCC
     * recipient's key and must NOT open with the To recipient's, which is the property that actually
     * keeps the two apart.
     */
```

### `fun aChangedKeyOutranksAMissingKey()`

```
    /**
     * A broken TOFU pin is not a missing key and must not be reported as one.
     *
     * `key_changed` means discovery found a key whose fingerprint does not match the pinned one —
     * which is what a key rotation looks like, and also what an interception attempt looks like.
     * Folding it into "no key on file" tells the user nothing changed at the exact moment the one
     * thing worth telling them did.
     */
```

### `fun theSentCopyIsEncryptedToTheVaultKeyNotAServerSuppliedOne()`

```
    /**
     * The Sent copy is encrypted to the public half of the **vault** key, never to anything the
     * server supplied.
     *
     * A hostile or compromised server that could hand back "your" public key would otherwise get a
     * readable copy of every message sent, with nothing on screen looking any different. Pinned by
     * decrypting with the vault key and proving the recipients' key cannot open it.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/DeviceEnvelopeTest.kt

### `fun aad_isUnambiguousAcrossAFieldBoundary()`

```
    /**
     * The reason the fields are length-prefixed rather than pipe-joined.
     *
     * With `info|deviceId|fingerprint`, an envelope sealed under (deviceId "dev|BADC0FFEE",
     * fingerprint "0123456789ABCDEF") produced byte-identical AAD to one sealed under (deviceId
     * "dev", fingerprint "BADC0FFEE|0123456789ABCDEF"), so each opened under the other. Length
     * prefixes make the framing unambiguous, which removes the class instead of arguing about
     * whether today's inputs can reach it.
     */
```

### `fun parse_acceptsAWellFormedEnvelope()`

```
    /**
     * The positive case, which did not exist before. Its absence is what let every other parse test
     * pass vacuously: under `org.json` from the stubbed `android.jar` the function returned null for
     * *every* input, so three assertions of `null` held against an implementation that validated
     * nothing. Replacing the whole body with `= null` left the suite green.
     */
```

### `fun aad_normalisesASpaceGroupedFingerprint()`

```
    /**
     * The repository's only fingerprint producer, [PgpFingerprint.compute], returns space-grouped
     * hex, while the browser strips whitespace before building its AAD. Normalising here is what
     * stops the natural implementation of the caller from producing an AAD that can never
     * authenticate — a failure the design classifies as hostile, and the browser reports to the user
     * as a substituted key.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpEncryptorTest.kt

### `class PgpEncryptorTest`

```
/**
 * [PgpDecryptor] is the oracle for every test here.
 *
 * A round trip through the app's own decrypt path is what makes these tests evidence rather than
 * self-agreement: the ciphertext has to satisfy the same packet walk, the same integrity check and
 * the same one-pass signature completion that a real inbound message does. A fixture generated and
 * checked by the code under test alone would prove only that the encoder agrees with itself.
 */
```

### `fun signedMessageVerifiesAgainstTheSignersPublicKey()`

```
    /**
     * The signature must complete through the one-pass path [PgpDecryptor.readLiteral] walks, which
     * requires the one-pass packet to precede the literal data and the signature packet to follow
     * it. Producing the packets in any other order still yields a message that decrypts, so only a
     * verified signature proves the nesting is right.
     */
```

### `fun failsRatherThanSkippingAnUnusableRecipientKey()`

```
    /**
     * A recipient whose key will not parse must fail the whole send, never be quietly dropped.
     *
     * Skipping is the dangerous behaviour: the message goes out, the UI reports success, and that
     * person silently receives mail they cannot read — or, on the delivery split, receives nothing
     * at all while the sender believes otherwise.
     */
```

### `fun encryptsToEveryRecipientKey()`

```
    /**
     * Every recipient key gets its own PKESK packet, and **both** recipients can open the message.
     *
     * Asserting only that the first key decrypts would pass on a message encrypted solely to that
     * key — and silently lock every CC'd recipient out in production.
     */
```

### `fun ownPublicKeyRoundTripsBackIntoAnEncryptionKey()`

```
    /**
     * The Sent copy is encrypted to this key, and it must come from the unlocked private key rather
     * than from anything the server supplied — a hostile server handing back an attacker's "your"
     * public key would otherwise get a readable copy of every message sent, with nothing on screen
     * looking different.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentRowTest.kt

### `class EnrollmentRowTest`

```
/**
 * Which row the Security page shows.
 *
 * A pure function so all nine outcomes are asserted here rather than through a 706-line Activity.
 * The ordering is as load-bearing as the mapping: two of these rows are LOCAL facts that must
 * survive the network being down, and the spec's table has them last.
 */
```

### `fun anInvalidatedKeyIsSaidRatherThanReadingAsUnEnrolled()`

```
    /**
     * A real state spec 1 produces — a biometric enrollment change or a Keystore invalidation kills
     * the vault key. It must be *said*, not silently read as un-enrolled: the server may still be
     * telling the user this device can read their mail, and they may decommission the device that
     * actually holds a working copy.
     */
```

### `fun localFactsSurviveTheNetworkBeingDown()`

```
    /**
     * **The ordering that matters most.** Both of these are local facts, and both are hidden by the
     * spec's table ordering the moment the identity request fails — which is exactly when a user is
     * most likely to be looking at this screen.
     */
```

### `fun hostileLocationOutranksALocalEnrollment()`

```
    /**
     * Hostile Location Protection outranks everything except pairing. Its contract is that no
     * envelope exists on this device, so an `ENROLLED` probe under it is a contradiction the row
     * must not repeat back to the user as "this device holds a key".
     */
```

### `fun theLockScreenCheckOutranksAnEnrolledStatus()`

```
    /**
     * The lock screen check must outrank the local status checks too, not just the identity branch.
     * `ENROLLED` under no secure lock screen is the same contradiction as under Hostile Location
     * Protection: without a lock screen the vault key cannot exist, so there is nothing to remove.
     */
```

### `fun theLockScreenCheckOutranksAnInvalidatedStatus()`

```
    /** Same contradiction for an invalidated key: without a lock screen there was never a vault key
     *  to have been invalidated, so there is nothing to report invalidated. */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCeremonyGateTest.kt

### `class EnrollmentCeremonyGateTest`

```
/**
 * Everything that must happen — or must NOT happen — before a keypair exists.
 *
 * The shared claim under all of these: a blocked ceremony leaves nothing behind. `newKeyPair()`
 * destroys any previous key and mints a fresh one, so calling it speculatively and giving up is not
 * free; and publishing a key the user then cannot use leaves the account's device row advertising an
 * enrollment key for a device that has none.
 */
```

### `fun hostileLocationProtectionBlocksBeforeAnyKeyIsMinted()`

```
    /**
     * Hostile Location Protection's contract is that no envelope exists on this device. Enrolling
     * under it would create exactly the artefact its teardown destroys.
     */
```

### `fun noSecureLockScreenBlocksBeforeAnyKeyIsMinted()`

```
    /**
     * `EnrollmentVault.ensureKey()` returns false without a secure lock screen, by design — the
     * envelope's protection *is* the lock screen. Saying so at the entry beats a biometric prompt
     * that cannot be satisfied after the user has already read a code aloud.
     */
```

### `fun anAccountWithNoIdentityIsUnavailableAndMintsNothing()`

```
    /**
     * Test 8 from the original 2b handoff — enrollment before an identity exists.
     *
     * There is nothing for the browser to seal, so a ceremony started here would show the user a
     * code and poll for five minutes against an envelope that can never arrive.
     */
```

### `fun aFailedCheckIsCouldNotCheckAndNotNoIdentity()`

```
    /**
     * The distinction decision 10 exists to protect. A failed check must not collapse into
     * [UnavailableReason.NO_IDENTITY]: those two render as different sentences to the user, and one
     * of them tells a user with a perfectly good identity to go and make another.
     */
```

### `fun hostileLocationIsCheckedBeforeTheIdentityRequest()`

```
    /**
     * Ordering matters, not just outcomes. Hostile Location Protection is a local declaration that
     * this network is hostile, so answering it must not require a request to a server on that
     * network first.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/DeviceEnrollmentCodeTest.kt

### `class DeviceEnrollmentCodeTest`

```
/**
 * Covers the short authentication string the user reads off this device and types into the browser
 * during device enrollment.
 *
 * The browser derives the same code from the public key **the server handed it** and refuses to
 * seal the account's private key if the two disagree. That makes this derivation a bit-for-bit
 * contract between three independent implementations, and a disagreement does not fail loudly: it
 * fails as "the codes never match" on every honest enrollment, which the browser reports to the
 * user as *"the key this server gave the browser is not the key on that device"*. An encoding bug
 * here reaches the user as an active attack.
 *
 * See `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`.
 */
```

### `fun normativeVector_matchesTheBrowsersCode()`

```
    /**
     * The normative vector, which until now had only ever been verified in the browser.
     * `frontend/src/lib/deviceEnrollment.test.ts` in kypost-server holds it as an inline snapshot
     * and is authoritative if it and the spec ever disagree — it runs on every frontend build.
     *
     * The key is a valid SEC1 encoding but deliberately **not** a point on P-256: the derivation
     * hashes bytes and must never need a curve operation, so this vector stays reproducible before
     * any ECDH is wired up.
     */
```

### `fun codeIsSeventyBitsWide()`

```
    /**
     * The code is 70 bits, not 50, and the length is load-bearing rather than cosmetic.
     *
     * With no commitment in the preimage the attacker's search is offline, so the only thing setting
     * its cost is the output width. At 50 bits a collision is ~2^50 SHA-256 compressions — about 14
     * GPU-hours and a few dollars per 120-second window — which is affordable for an adversary who
     * can write the relay's device table. A silent regression to a shorter code would not fail any
     * other test here, because the shorter code is a prefix of the longer one.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpFingerprintSubkeyJvmTest.kt

### `class PgpFingerprintSubkeyJvmTest`

```
/**
 * [PgpFingerprint.compute] on keys that carry an encryption subkey — the shape every real account's
 * key has, and the only shape that reaches `hasValidBindingSignature`.
 *
 * Every pre-existing fixture is a bare primary key with no subkey, so that function had no test at
 * all. It was also the one place still using Bouncy Castle's Jca verifier, which asks the platform
 * JCA for an EdDSA `KeyFactory` that Android does not have — so on a real phone every ed25519 key
 * was rejected as unparseable while these JVM tests stayed green on a JDK that does have EdDSA.
 * `PgpFingerprintSubkeyDeviceTest` is the on-device half of this pair; both must exist, because
 * either one alone is exactly what missed the bug.
 */
```

### `fun graftedForeignSubkey_returnsNull()`

```
    /**
     * The rejection half. A subkey bound by a *foreign* primary's signature must not be accepted:
     * the caller persists the whole blob, so a grafted subkey the user's one fingerprint check
     * never covered is key material smuggled in behind a verified label.
     *
     * Built by grafting the donor key's subkey onto the fixture's ring, which leaves the donor's
     * binding signature in place over the wrong primary — the precise thing verification exists to
     * catch, and a case no amount of parsing alone would notice.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentReportOutcomeTest.kt

### `class EnrollmentReportOutcomeTest`

```
/**
 * The worker's retry decision, tested as a pure function.
 *
 * It lives apart from the worker so it can be asserted without a device: the mapping is the
 * security-relevant part — a wrong branch here either drops a correction the server needs, or
 * spins forever against a credential the server will never accept.
 */
```

### `fun retryingStopsAtTheAttemptCeiling()`

```
    /**
     * Retrying is bounded.
     *
     * WorkManager applies no attempt ceiling of its own — verified against work-runtime 2.10.1,
     * which only clamps the backoff at five hours — so an unbounded RETRY is a work item that never
     * terminates, waking for the life of the install against a relay that may have been
     * decommissioned years earlier.
     */
```

### `fun aMissingDeviceRowIsDoneNotARetry()`

```
    /**
     * 404 on this route means the device row is gone — deregistered, or the account was deleted.
     * There is nothing left to correct, so this is done rather than a retry loop against a row that
     * will never come back.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpEncryptorKeyValidationTest.kt

### `class PgpEncryptorKeyValidationTest`

```
/**
 * Recipient key material arrives from the relay and is attacker-influenceable, so
 * [PgpEncryptor.encrypt] must validate it locally rather than trusting the server's `usable` verdict.
 *
 * These cover the shapes a run-8 audit reproduced against the unvalidated selector: it filtered only
 * on `isEncryptionKey` — which ignores revocation — and took `lastOrNull()` across every ring in the
 * blob, with no check that the blob held exactly one ring.
 *
 * The expected outcome is [EncryptResult.Failed] rather than a skipped recipient, matching the
 * contract `encrypt` already documents: a recipient whose key carries no usable encryption key is a
 * hard failure, because skipping means that person silently cannot read their own mail while the
 * sender is told the message went out.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpMessageStateTest.kt

### `fun errorTakesPrecedenceOverMissingBody()`

```
    /**
     * The error wins over an empty body. Both conditions hold at once for a failed decrypt, and
     * reading it as CLIENT_PROTECTED would send the user to webmail for a message that fails
     * there too, hiding a reason the server already gave us.
     */
```

### `fun correctlySignedMailIsNotAnAccusation()`

```
        // The relay does not verify signed-but-unencrypted mail at all, so pgpVerified is
        // permanently false for that whole population. Reading signed && !verified as INVALID
        // fired "Signing Key Mismatch" on every correctly signed message and marked every such
        // row with ⚠ — training the user to ignore the marker that also carries KEY_CHANGED.
        //
        // An empty fingerprint means nothing was checked against anything.
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpComposeStateTest.kt

### `fun clientCustodyEnrolled_offersBothAndEncryptsOnThisDevice()`

```
    /**
     * An enrolled device holds the account's private key, so it can encrypt and sign locally.
     *
     * [PgpComposeState.clientSide] is what routes the send to `/api/mail/send-pgp` instead of
     * `/api/mail/send`; without it the compose screen would offer toggles and then post them to the
     * endpoint that answers 409 for exactly this account type.
     */
```

### `fun clientCustodyEnrolledWithoutAnAccountAddress_handsOffInstead()`

```
    /**
     * Enrolled but no account address: every delivery's `From` must equal the authorized address,
     * and there is none to write. Offering Send here would build ciphertext the relay 403s, so this
     * degrades to the handoff instead.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/OffersCheckAgainTest.kt

### `class OffersCheckAgainTest`

```
/**
 * "Check again" is the only way forward from every state that stops with the keypair still live, so
 * a missing row here strands the user on a screen whose only other exit destroys the published key.
 * That is a JVM test rather than something visible only on a running screen.
 */
```

### `fun aDismissedPromptCanBeResumed()`

```
    /**
     * The state a dismissed fingerprint prompt lands on. The envelope is already on the relay and
     * the keypair is what opens it, so this is precisely the state where resuming must be possible —
     * and it carries no code, so no other affordance on the screen can substitute for the button.
     */
```

### `fun aCodeLeftWithNoWindowBehindItOffersIt()`

```
    /**
     * Defensive, and deliberately kept. A window that ends normally emits `WaitingTimedOut`, and the
     * cancelled prompt now lands on `ReadyToFinish`, so no designed path rests here — but a poll loop
     * that unwinds on a throw leaves the last emitted state as `ShowingCode` with `run()`'s `finally`
     * having set idle. Offering the button is the only way forward from that; the alternative is a
     * screen whose sole exit destroys a published key.
     */
```

### `fun spentAndTransientStatesDoNotOfferIt()`

```
    /**
     * Terminal and transient states must not. Enrolled and Failed have both destroyed the keypair,
     * so "Check again" would resume against a key that no longer exists.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/WebmailDeepLinkTest.kt

### `fun everyBuiltUrlPassesTheFirstPartyGuard()`

```
    /**
     * The seam between the builders and [isFirstPartyWebmailUrl]: whatever these produce must
     * survive the guard that decides whether it may be opened at all.
     *
     * Both sides are tested apart, and neither test would notice them drifting. A builder change
     * that moved the host, dropped the port or switched the scheme would leave every assertion
     * above green and turn both handoffs into a refusal log line and a toast — a dead button on
     * the only route a client-custody account has to its own mail. The shapes below are the ones a
     * real pairing produces: a trailing slash, a redundant :443, a non-default port, a server
     * mounted under a path, and a host the user typed in caps.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/Sec1PointTest.kt

### `class Sec1PointTest`

```
/**
 * Covers the SEC1 encoding of a P-256 public key — a bit-for-bit contract shared with a Go server
 * and a TypeScript browser client. A deviation does not fail loudly: it fails as "the codes never
 * match" on every honest enrollment, which the browser reports to the user as an active attack.
 *
 * These live as JVM tests on purpose. The instrumented test can only assert the overall length of a
 * *randomly generated* key, and the interesting branch — a coordinate whose big-endian form is
 * shorter than 32 bytes, so it must be left-padded rather than truncated — occurs in roughly one
 * random key in 128. It was effectively never covered.
 */
```

### `fun coordinateWithASignByteIsStripped()`

```
    /**
     * A coordinate whose top bit is set: `BigInteger.toByteArray()` prepends a 0x00 sign byte and
     * returns 33 bytes. The sign byte must be stripped, not carried into the encoding. Happens for
     * roughly half of all real keys.
     */
```

### `fun shortCoordinateIsLeftPaddedNotTruncated()`

```
    /**
     * The branch the instrumented test almost never reaches: a small coordinate must be LEFT-padded
     * with zeros to 32 bytes. Getting this wrong right-aligns the value or shortens the point, and
     * every code derived from it disagrees with the browser's.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpDecryptorTest.kt

### `class PgpDecryptorTest`

```
/**
 * These run on the JVM against a gpg-produced vector. `isReturnDefaultValues = true` is project-wide,
 * so a decryptor that reached for an Android framework class would silently resolve to a stub and
 * these would pass against an implementation that does nothing — which is exactly how
 * `parseDeviceEnvelope` once returned null for every input under three passing tests. Hence
 * [PgpDecryptor] uses Bouncy Castle's lightweight `Bc*` operators and no Android imports at all.
 */
```

### `private val signerKeys`

```
    /** The signer keys the reader will pass in production: [TestPgpPrivateKey.ARMORED_PUBLIC] is
     *  the same key pair's public half, exported separately by `gpg`, exactly the shape a real
     *  caller holds — [SignerBinding] only ever supplies keys the address book bound to the
     *  displayed sender, never the sender's own message. */
```

### `fun failsClosedOnAnUnprotectedMessage()`

```
        // ARMORED_UNPROTECTED_MESSAGE is a legacy Symmetrically Encrypted Data (tag 9) packet, made
        // with `gpg --rfc2440 --disable-mdc` — not the Sym. Encrypted Integrity Protected Data
        // (tag 18) packet every other fixture here uses. Accepting it would mean a tampered
        // ciphertext could render as an ordinary message: this is the one case the reader can never
        // trust the server not to have produced.
```

## app/src/test/java/org/kysecurity/mail/pgp/WebmailOriginTest.kt

### `class WebmailOriginTest`

```
/**
 * Covers the guard on the webmail handoff, and the launch order it feeds.
 *
 * The handoff is the one place the app tells the user "this is your mail, sign in here", so
 * only URLs whose origin equals the paired server's are eligible; everything else is refused
 * outright rather than degraded to a browser launch.
 */
```

### `fun `tries the pwa first, then any browser`()`

```
    /**
     * The order is the whole contract: a PWA attempt cannot be predicted, only tried, so the list
     * must lead with it and still hold a fallback for the (usual) case where it fails.
     */
```

### `fun `never launches webmail inside this app's own task`()`

```
    /**
     * A Custom Tab renders inside KyPost's own task, where this app's FLAG_SECURE does not reach
     * the browser's window — so decrypted mail could appear in the KyPost Recents card. Every mode
     * that survives here launches into some other app's task. This is the regression test for that;
     * `WebmailLaunchMode` no longer has a CUSTOM_TAB entry to return, and re-adding one has to fail
     * here before it can ship.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/LocalSignerKeyMappingTest.kt

### `class LocalSignerKeyMappingTest`

```
/**
 * The two decisions that turn a contact row into a trust input.
 *
 * Both feed [signatureStateFor]'s local branch, which is the only branch that can produce
 * `VERIFIED_CONFIRMED`. Getting either wrong hands the strongest claim in the app to the wrong row.
 */
```

### `section banner: address matching`

```
    // --- address matching ---

```

### `section banner: what may be offered, and what may be confirmed`

```
    // --- what may be offered, and what may be confirmed ---

```

## app/src/test/java/org/kysecurity/mail/pgp/PgpFingerprintTest.kt

### `class PgpFingerprintTest`

```
/** [TEST_KEY] is a disposable ed25519 key generated with `gpg --quick-generate-key` purely as a
 *  fixture — [TEST_KEY_FINGERPRINT] is gpg's own reported fingerprint for it, letting these tests
 *  confirm [PgpFingerprint.compute] agrees with a real, independent OpenPGP implementation rather
 *  than just round-tripping through the same Bouncy Castle code it's built on. */
```

### `fun compute_trailingSecondKeyRing_returnsNull()`

```
    /**
     * Callers persist the WHOLE armored blob, so a fingerprint that describes only part of it cannot
     * be meaningfully confirmed by a human comparing one string. Bouncy Castle's key-ring stream
     * constructor stops at a second PUBLIC_KEY packet, which made an appended ring invisible here
     * while still being saved and uploaded — the user verified one key and stored two.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/RendersNothingTest.kt

### `class RendersNothingTest`

```
/**
 * The blank-screen case.
 *
 * `renderPgpBar`'s own KDoc says "Silence here is what the old build did, and it read as 'this email
 * is blank'". That was fixed for every encrypted state and left open for [PgpMessageState.NONE],
 * which is exactly where an encrypted-but-unwarmed message lands: `pgpEncrypted` is `omitempty`
 * server-side and defaults to false here, so it arrives flagged as ordinary mail with no body.
 */
```

### `fun aPreviewIsSomethingToShow()`

```
    /**
     * The preview is the fallback the detail view already renders for [PgpMessageState.NONE], so a
     * message carrying one is not blank and must not be labelled as such.
     */
```

### `fun aStateThatExplainsItselfIsNotBlank()`

```
    /**
     * Every other state already puts its own notice on screen, and saying "nothing to show" beside
     * "this message is end-to-end encrypted" would contradict it. CLIENT_PROTECTED in particular
     * renders an empty body **on purpose**.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpBootstrapClientTest.kt

### `fun parsesTheAccountAddressFromSuggestedUserIds()`

```
    /**
     * The account address every client-encrypted delivery's `From` header must equal.
     *
     * `suggestedUserIDs[0]` is the server's own `strings.TrimSpace(payload.Username)` — the very
     * expression `handleMailSendPGP` feeds to `resolveMailFrom` — so it is authoritative rather than
     * a guess. Deriving it from the public key's User ID instead would diverge for an imported key,
     * and the symptom is a 403 after the ciphertext has already been built.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCodeFormatTest.kt

### `class EnrollmentCodeFormatTest`

```
/**
 * The code is transcribed by a human across two devices, which is the failure the grouping exists
 * to prevent. Four groups of at most four is the pattern people already read off bank cards; two
 * groups of seven are long runs that are easy to lose your place in, and an omitted character in a
 * long run is silently wrong rather than visibly a wrong-length group.
 *
 * The browser's `formatEnrollmentCode` must group identically — see
 * `kypost-server/frontend/src/lib/deviceEnrollment.ts`. Grouping never reaches the hash:
 * `normalizeEnrollmentCode` strips `/[\s-]/g` before comparing.
 */
```

### `fun neverDropsCharacters()`

```
    /**
     * The guard the browser's own suite already carries, for the same reason: a hardcoded slice
     * silently TRUNCATED the code when its width grew from 10 to 14 — and because the short code is
     * a prefix of the long one, the truncated form looked entirely plausible while dropping the four
     * characters carrying the extra 20 bits.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/FakeReaderPorts.kt

### `internal fun successPayload(...)`

```
/** `PgpPayloadResult.Success` has no default values for any field, so every fixture that stands in
 *  for a fetched payload goes through here rather than constructing `Success` directly. `sender` and
 *  `resolvedSender` default to the same address the tests' own `read()` helper defaults `sender` to,
 *  since production always has the server compute both from the same message.
 *
 *  Defaults to [TestPgpPrivateKey.ARMORED_MIME_MESSAGE], not [TestPgpPrivateKey.ARMORED_MESSAGE]:
 *  the latter's plaintext is bare text with no MIME headers, so [PgpMimeReader] can never parse it
 *  and every test that needs the reader to actually reach `Decrypted` would fail past decryption. */
```

### `internal fun detachedSignedPayload(...)`

```
/** A signed-but-not-encrypted payload: `encryptedPayload` blank, `body` readable,
 *  `signaturePayload` a detached signature over it — the shape `PgpPayloadClient` returns for
 *  RFC 3156 clear-signed mail. Defaults to [TestPgpPrivateKey.DETACHED_SIGNATURE_BODY] signed by
 *  [TestPgpPrivateKey.ARMORED_DETACHED_SIGNATURE], both verified independently with `gpg --verify`
 *  before being wired in here, so `EncryptedMessageReader`'s `payload.encryptedPayload.isBlank()`
 *  branch has a real fixture to run against instead of never executing at all (it previously had
 *  none — `successPayload` always sets a non-blank `encryptedPayload`). */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentPointValidationTest.kt

### `class EnrollmentPointValidationTest`

```
/**
 * The on-curve check that stands between an attacker-supplied ephemeral public key and this
 * device's enrollment private key.
 *
 * `parseDeviceEnvelope` checks the blob is 65 bytes starting `0x04`. That is a length-and-prefix
 * check: it says nothing about whether (x, y) satisfies the curve equation, which is the
 * precondition for an invalid-curve attack. Before this validator the only thing rejecting such a
 * point was whichever `KeyFactory` provider happened to resolve at runtime — a property this
 * codebase asserts nowhere and does not control.
 *
 * Pure math on `java.security.spec` types, so it runs on the JVM rather than needing a device.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpMimeReaderTest.kt

### `fun walkKeepsRealContentWhenALaterSiblingOfTheSameSubtypeIsBlank()`

```
        // The other direction of the same fix as walkPrefersFirstNonBlankPartOverAnEarlierBlankSibling:
        // once the slot holds real content, a later blank sibling of the same subtype must not
        // overwrite it and blank a message that was already readable.
```

### `fun walkKeepsAnAllBlankMultipartAsEmptyStringNotNull()`

```
        // The other half of the same fix: a blank part is still real content when nothing better ever
        // turns up. A multipart whose only text/html part is empty must yield "" and a non-null
        // DecryptedBody, not null.
```

## app/src/test/java/org/kysecurity/mail/pgp/RecipientFieldsTest.kt

### `class RecipientFieldsTest`

```
/**
 * The per-field recipient split behind the delivery grouping.
 *
 * Deliberately **not** [org.kysecurity.mail.splitAddresses], which flattens To/CC/BCC into one list and
 * dedupes across them. That is right for the preflight, where the question is "which addresses need
 * a key" and asking twice about one person is just noise. Here it would collapse a BCC into the To
 * bucket — putting a blind recipient in a header every other recipient can read.
 */
```

### `fun anAddressInBothToAndBcc...`

```
    /**
     * An address in both To and BCC is not a blind recipient — it is already visible in the To
     * header. Keeping it in the BCC bucket would build it a second, redundant delivery *and* leave
     * the sender believing that copy was blind.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpIdentityStatusTest.kt

### `the account fingerprint test`

```
    /**
     * The account's own fingerprint comes from the bootstrap response's `publicKey`, hashed
     * locally. The self-contact's `pgpKey` column — what the QR screen used to read — is an
     * ordinary, independently-editable contact field with no connection to the account's real PGP
     * identity (see [org.kysecurity.mail.contacts.contactHasLinkedPgpKey]), so it is empty for every
     * user who never manually attached a key to their own contact row, and the screen showed
     * "your fingerprint is unavailable" to everyone.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentSessionTest.kt

### `the process-wide reset test`

```
    /**
     * The holder must be reachable from the process-wide reset, not only from the app lock.
     *
     * `ProcessState.resetAll()` is what the security wipe, `AppRestart.relaunch` and the unpair
     * purge all go through, and it resets only holders that registered. An unregistered holder is
     * not merely missed — `resetAll()` returns it in no failure list, so the wipe's
     * `step("inMemoryPlaintext")` records success and the wipe reports Complete with the account's
     * opened private key still in the heap of a process the relaunch does not kill.
     */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpDecompressionBombTest.kt

### `class PgpDecompressionBombTest`

```
/**
 * A sender-controlled decompression bomb must be a failed message, not a dead app.
 *
 * `readAllWithLimit` caps the *literal* data at 32 MB. Nothing capped how many nested compressed
 * packets were unwrapped on the way to it, and each layer allocates a fresh object factory over a
 * fresh inflater. Since the message stays in the mailbox, the failure repeats on every open — an
 * unopenable app rather than an unopenable message. Every input here is chosen by whoever sent the
 * mail, which is the entire threat model of a mail client.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/RecipientResolveClientTest.kt

### `class RecipientResolveClientTest`

```
/**
 * `/api/pgp/recipients/resolve` differs from `/check` in more than its payload: it answers **JSON**
 * on 409 and 413 as well as 200, where `/check` is JSON only on 200. Getting that wrong means
 * running a decoder over a plain-text body and reporting "malformed response" for what is really a
 * categorical refusal.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/EnrollmentCountdownTest.kt

### `class EnrollmentCountdownTest`

```
/**
 * The countdown's pure arithmetic — see [expiryCountdown]'s KDoc for why `nowMs` is a parameter
 * rather than a clock read internally.
 *
 * Comfortably positive, exactly 1, exactly 0, and already-past are the four cases a fix-round
 * review asked this extraction to cover. Exactly 1 is also the case that would, on its own, have
 * caught "This code changes in 1 seconds." — the `enrollment_code_expiry` string rendered through
 * `getString` instead of `getQuantityString` before it became a `<plurals>` resource — since a
 * test asserting `remainingSeconds == 1` forces a look at what actually renders it.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/VaultOpenerContractTest.kt

### `class VaultOpenerContractTest`

```
/**
 * The port's contract, not the Keystore. `AndroidVaultOpener` needs hardware and is covered by the
 * instrumented suite; what a JVM test can pin is the property the whole design rests on: an
 * [OpenOutcome] never carries key material, so no key can travel back through the orchestrator.
 */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpKeyActivityTest.kt

### `class PgpKeyActivityTest`

```
/** Covers [PgpKeyActivity.parsePgpQrKeyUrl] — a pure function with no Android framework
 *  dependency, so it's plain-JVM testable like [PgpQrClientTest]'s coverage of [PgpQrClient]. No
 *  mocking framework, matching this repo's house style. */
```

## app/src/test/java/org/kysecurity/mail/pgp/PgpQrClientTest.kt

### `section banner: mintToken`

```
    // ---- mintToken ----

```

### `section banner: fetchKey`

```
    // ---- fetchKey ----

```

