# Comment archive - androidTest

Comments removed from `app/src/androidTest/**` by the ponytail comment sweep, kept verbatim.

## app/src/androidTest/java/org/kysecurity/mail/contacts/ContactSyncRaceRegressionTest.kt

### `class ContactSyncRaceRegressionTest`

```
/**
 * Regression test for the `isSelf`-clobbering race between [ContactSyncRepository.sync] (server
 * pull, full-row upsert) and `DeviceContactRepository.pullDeviceChangesForOwnAccount` (read the
 * row, merge a few fields, write the whole row back) — both hit the same Room `contacts` table
 * from independent coroutine scopes with [ContactDao.upsertAll] replacing whole rows. Confirmed in
 * production via a real device's local DB showing `isSelf=0` after the server had already flipped
 * it to true. [ContactSyncRepository.syncMutex] — held around both call sites — fixes it by
 * ensuring one side's read can never observe stale data from before the other side's write.
 */
```

Replaced with: `/** ContactSyncRepository.syncMutex serializes server sync vs device pull so isSelf survives. */`

## app/src/androidTest/java/org/kysecurity/mail/contacts/device/DeviceContactAccountTeardownTest.kt

### `class DeviceContactAccountTeardownTest`

```
/**
 * The sync account is what the contacts teardown now rests on, in two places, so it needs to
 * actually answer.
 *
 * - `DeviceContactPurge.deleteSyncedRows` uses [DeviceContactAccountManager.accountExists] to tell
 *   "the contacts permission was revoked and rows may survive" from "nothing was ever published".
 * - `SecurityWipe`'s `deviceContactAccount` step uses it to decide whether a failed removal is a
 *   reportable failure. Removing the account is what makes CP2 hard-delete the raw contacts under
 *   it, so it is the last thing standing between a wipe and an address book left outside the
 *   sandbox.
 *
 * Both used to be unasserted: nothing in either test tree touched `removeAccountBlocking`,
 * `accountExists` or `deleteSyncedRows`.
 */
```

Replaced with: `/** DeviceContactPurge and SecurityWipe both rest on these account calls. */`

### `fun deleteSyncedRows_withNoAccount_isNotAFailure()`

```
    /**
     * With no account present the purge reports 0 (nothing could exist), never a failure. This is
     * the case that made every wipe on a device that never enabled sync report Incomplete when the
     * denied-permission branch was first tightened, so it is pinned here.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/contacts/ExpandableSectionViewTest.kt

### file header (above `package`)

```
// app/src/androidTest/java/org/kysecurity/mail/contacts/ExpandableSectionViewTest.kt
```

### `private val context = ContextThemeWrapper(`

```
    // The header layout references ?attr/selectableItemBackground (view_expandable_section_header.xml),
    // an AppCompat/MaterialComponents theme attribute. The bare instrumentation targetContext isn't
    // themed (it resolves to the plain framework theme), so it fails to inflate with
    // "Failed to resolve attribute" — wrap it in the app's real theme, exactly like every Activity in
    // this app gets via the manifest's android:theme="@style/Theme.KyPost".
```

Replaced with: `// Header needs ?attr/selectableItemBackground; the bare targetContext theme can't resolve it.`

## app/src/androidTest/java/org/kysecurity/mail/contacts/RecipientMatchingInstrumentedTest.kt

### `class RecipientMatchingInstrumentedTest`

```
/** [isValidEmailFormat] wraps [android.util.Patterns.EMAIL_ADDRESS], a real Android framework
 *  class — its static fields aren't initialized under the plain-JUnit `app/src/test` stub jar
 *  (see `app/src/test/AGENTS.md`: "Avoid ... Android framework dependencies in JVM unit tests"),
 *  so this coverage lives here instead. */
```

Replaced with: `/** Patterns.EMAIL_ADDRESS is unusable in JVM unit tests, so this coverage lives here. */`

## app/src/androidTest/java/org/kysecurity/mail/contacts/RepeatableFieldListTest.kt

### file header (above `package`)

```
// app/src/androidTest/java/org/kysecurity/mail/contacts/RepeatableFieldListTest.kt
```

## app/src/androidTest/java/org/kysecurity/mail/data/ContactDaoOrderingTest.kt

### `class ContactDaoOrderingTest`

```
/** Mirrors [ContactDaoSearchTest]'s in-memory-DB setup; covers [ContactDao.observeAll]'s
 *  self-contact-first ordering rather than [ContactDao.search]'s substring matching. */
```

## app/src/androidTest/java/org/kysecurity/mail/data/DataGraphHostileLocationTest.kt

### `fun enablingAfterExistingOnDiskDatabase_deletesThePreToggleFile()`

```
    /**
     * Reproduces finding C1 (2026-07-22 spec's final-review fix round): the two tests above only
     * prove *in-memory Room never creates a file* — they say nothing about whether turning
     * Hostile Location Protection *on* actually deletes a database file that already existed from
     * before the toggle. This exercises the exact sequence
     * [org.kysecurity.mail.security.SecuritySettingsActivity]'s `hostileLocationSwitch` listener runs
     * in production (`SecurityWipe.closeAndDeleteDatabase` then `HostileLocationSettings.setEnabled(true)`,
     * then — standing in for the process restart `AppRestart.relaunch` would otherwise do — a
     * fresh `DataGraph(context)` construction) and asserts nothing from before the toggle
     * survives: the old file is gone, and the rebuilt graph is in-memory-only.
     */
```

### `DataRuntime.invalidate()`

```
        // Drop any graph built earlier in this instrumentation run. DataRuntime is a
        // process-lifetime singleton and DataGraph picks in-memory vs. disk-backed ONCE, at
        // construction — so a graph built by an earlier class while protection was on stays
        // in-memory no matter what the flag says now, and the precondition below fails with
        // "on-disk DB must exist" for a reason that has nothing to do with what this test asserts.
        // Latent since this test was written; it surfaced when a sibling suite started exercising
        // the enabled posture more.
```

Replaced with: `// DataGraph picks memory vs disk once at construction; drop graphs from earlier tests.`

### `DataRuntime.graph(context).database.openHelper.writableDatabase`

```
        // DataRuntime is a process-lifetime singleton (see SingletonGraph) — using it here (not
        // a standalone `DataGraph(context)`, unlike the two tests above) matters: it's the same
        // instance production code (and SecurityWipe.closeAndDeleteDatabase below) reaches via
        // DataRuntime.graph(context) elsewhere in the app, so this reproduces the real call chain
        // rather than a disconnected copy of it.
```

Replaced with: `// Use the DataRuntime singleton — the instance SecurityWipe.closeAndDeleteDatabase reaches.`

### `val rebuiltGraph = DataGraph(context)`

```
        // Standing in for the process restart AppRestart.relaunch would otherwise do: a fresh,
        // independent DataGraph (not through the now-stale DataRuntime singleton — see
        // SecurityWipe.wipeAndResetApp's caller contract) must come up in-memory and must not
        // resurrect the deleted file.
```

Replaced with: `// Stands in for the AppRestart.relaunch restart: a fresh graph, not the stale singleton.`

## app/src/androidTest/java/org/kysecurity/mail/data/EmailDaoClearDecryptedTest.kt

### `class EmailDaoClearDecryptedTest`

```
/**
 * [EmailDao.clearServerDecryptedBodies] against a real database.
 *
 * The JVM fake in `MailRepositoryTest` mirrors the predicate in Kotlin, which cannot catch the ways
 * the SQL itself can be wrong: a boolean compared against the wrong literal, or `body != ''` silently
 * excluding every row because SQL comparison with NULL yields NULL rather than true. A query that
 * matches nothing would leave the plaintext in place and every JVM test would still pass.
 */
```

Replaced with: `/** clearServerDecryptedBodies against real SQL; the JVM fake only mirrors the predicate. */`

## app/src/androidTest/java/org/kysecurity/mail/data/DatabaseEncryptionTest.kt

### `class DatabaseEncryptionTest`

```
/**
 * `kypost_mail.db` holds every cached message body, the whole contact book and contacts' PGP keys,
 * and it was a plain SQLite file — readable by anyone who could get the file off the device,
 * whatever the app lock said. These tests are the evidence that it no longer is.
 *
 * Instrumented rather than JVM because SQLCipher is a native library: a unit test would prove
 * nothing about what actually lands on disk.
 */
```

Replaced with: `/** Instrumented, not JVM: SQLCipher is a native library, so only on-device bytes prove anything. */`

### `fun setUp()`

```
        // The tests below open Room directly rather than through DataGraph, so they have to do
        // what DataGraph's factory does: load the native library, and make sure `databases/`
        // exists. Both were real findings — the AAR loads nothing itself, and SQLCipher's helper
        // does not create the directory the framework helper creates on demand.
```

Replaced with: `// Room is opened directly here, so do what DataGraph does: load the lib, make databases/.`

### `private fun startsWithSqliteHeader(file: File): Boolean`

```
        // Spelled out byte by byte rather than reused from production, so the test cannot agree
        // with a bug in the code it is checking — which is exactly what happened: both said
        // "SQLite format 3 " with a trailing space, where the real magic ends with a NUL.
```

Replaced with: `// Spelled out byte by byte, not reused from production, so the test cannot share its bug.`

### `fun messageBodiesAreNotReadableInTheDatabaseFile()`

```
    /**
     * The claim in one test: a message body written through Room does not appear as plaintext in
     * the file on disk, and the file is not a readable SQLite database at all.
     */
```

### `fun aPlaintextDatabaseDoesLeakTheBody()`

```
    /** The control: without the openHelperFactory this test would pass vacuously, so prove that a
     *  plaintext database really does leak the body. If this ever fails, the assertion above is
     *  not testing what it claims. */
```

Replaced with: `/** Control for [messageBodiesAreNotReadableInTheDatabaseFile] — proves it is not vacuous. */`

### `fun anExistingPlaintextDatabaseIsConvertedWithoutLosingRows()`

```
    /**
     * The upgrade path for every existing install: an unencrypted database is converted in place,
     * every row survives, and Room's `user_version` is carried across so it does not try to re-run
     * migrations against an already-migrated schema.
     */
```

### `fun aConversionInterruptedBeforeTheRenameIsRecovered()`

```
    /**
     * The crash window, asserted rather than claimed.
     *
     * The conversion used to `delete()` the plaintext file and then `renameTo()` the converted one.
     * A process death between those two lines left no database and an orphaned `.encrypting` file
     * holding the whole mailbox — which the old `if (!plain.exists()) return true` read as "nothing
     * to convert", so Room created an empty database over the top and the user's mail was gone. The
     * KDoc above the delete asserted this could not happen.
     *
     * Simulated exactly: run a real conversion, then put the file system into the state that window
     * produced, and require the next call to recover.
     */
```

### `fun anOrphanUnderADifferentKeyIsDiscardedRatherThanAdopted()`

```
    /**
     * An orphan this device cannot read must be discarded, not renamed into place: replacing a
     * recoverable empty state with an unopenable database is strictly worse.
     */
```

### `fun aFileTooShortToHoldTheHeaderIsNotTreatedAsPlaintext()`

```
    /**
     * The header check reads sixteen bytes and used to discard `read()`'s count, so a short read
     * zeroed the tail and reported a plaintext database as already encrypted — which hands a
     * plaintext file to SQLCipher.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/data/MigrationTest.kt

### `class MigrationTest`

```
/**
 * Verifies MIGRATION_3_4 (Task 2 extended contact fields) applies cleanly against a real
 * version-3 `contacts` table, matching the instrumentation-test convention documented in
 * app/src/androidTest/AGENTS.md (MigrationTestHelper needs Android's real SQLite, which JVM
 * unit tests under app/src/test can't provide).
 */
```

Replaced with: `/** MigrationTestHelper needs Android's real SQLite, so migration coverage lives here. */`

### `fun migrate9To10_addsTheIdentityAlarmColumnWithoutDisturbingTheKeyAlarm()`

```
    /**
     * Additive and defaulted, so existing rows keep their key alarm and start with no identity
     * alarm. That is the safe direction: a missing identity alarm is re-raised by the next sync that
     * observes a rebind, whereas migrating every existing key alarm into both columns would show
     * users a review prompt they cannot action.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/KeywordSettingsBoundsTest.kt

### `class KeywordSettingsBoundsTest`

```
/**
 * Keywords are the relay's unvalidated per-message `label`, and the remembered set is rendered as
 * one un-recycled `Chip` per entry during `InboxActivity.onCreate`. Unbounded, a single inbox
 * response could brick the app permanently: ~50k labels threw `OutOfMemoryError` inside `onCreate`,
 * the Keyword Settings screen (the only in-app cleanup) died the same way, and this prefs file
 * survived unpairing — so re-pairing to a clean server did not recover.
 */
```

Replaced with: `/** Unbounded keywords could OOM InboxActivity.onCreate permanently, so the set is capped. */`

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentEnvelopeRoundTripTest.kt

### `class EnrollmentEnvelopeRoundTripTest`

```
/**
 * The one thing no JVM test can do: a real ECDH against a non-extractable P-256 key in this device's
 * Keystore, opened with the same envelope format the browser produces.
 *
 * The JVM suite proves the state machine routes every branch correctly; this proves the branch it
 * routes to actually works. Without it, an AAD or HKDF-salt mistake would surface to a user as the
 * substituted-key alarm — this feature's one alarm — on every honest enrollment.
 *
 * **Requires a secure lock screen** for the vault half. See the `locksettings set-pin` step in
 * `.github/workflows/ci.yml`; on a bare emulator `ensureKey()` returns false by design.
 *
 * **`sealCipher()` is deliberately not exercised here.** The vault key is
 * `setUserAuthenticationRequired(true)` with per-use auth, so `Cipher.init(ENCRYPT_MODE, ...)`
 * cannot succeed outside a satisfied `BiometricPrompt` — it returns null, and a test asserting that
 * would be asserting the absence of authentication rather than the presence of encryption. The spec
 * lists `sealCipher` under instrumented coverage; it is not reachable, and that is stated rather
 * than papered over with a test that passes for the wrong reason. `openCipher` IS reachable
 * (`Cipher.init` on GCM needs no authentication) and is already covered by `EnrollmentStateTest`
 * through `probeEnrollment`.
 */
```

Replaced with: `/** sealCipher is unreachable here: its key needs per-use auth from a BiometricPrompt. */`
(The secure-lock-screen requirement survives in the `vault.ensureKey()` assertion message.)

### `assertNull(EnrollmentVault(...).stored())` in `fun theVaultStoresAndDestroysWhatTheCeremonyWouldWrite()`

```
        // Asserting on `vault` here — the instance held across the teardown — would be pinning a
        // contract nothing depends on. EnrollmentVault caches its EncryptedSharedPreferences in a
        // `by lazy`, and EnrollmentTeardown destroys through a DIFFERENT instance of its own
        // (EnrollmentTeardown.kt:26), so an instance held across a teardown reports stale state: it
        // still sees the blob that instance itself wrote, even though the file backing it is gone.
        // That is a real, latent bug (tracked, not fixed here), but no production caller hits it —
        // every construction site builds a fresh EnrollmentVault at the point of use
        // (EnrollmentStateWorker.kt:89, DeviceEnrollmentActivity.kt:128, EnrollmentTeardown.kt:26,
        // SecuritySettingsActivity.kt:324). A fresh instance after a teardown seeing nothing is the
        // contract every one of those callers actually relies on, so that is what this asserts.
```

Replaced with: `// An instance held across teardown reports stale state; callers always build a fresh one.`

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentKeyStoreTest.kt

### `fun newKeyPairRotatesRatherThanReusing()`

```
    /**
     * The key must ROTATE, not persist. It used to be idempotent — `ensureKeyPair` returned early
     * when the alias existed — and that made it a permanent, unauthenticated Keystore key.
     *
     * Two consequences, both real. It became a standing path to every envelope the relay has ever
     * retained, openable with no prompt of any kind, which defeats [EnrollmentVault]'s per-use
     * authentication by a parallel route. And it gave an attacker unbounded lead time to precompute
     * against a stable, known public key, which is what makes grinding the enrollment code
     * affordable.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentRowStringsTest.kt

### `class EnrollmentRowStringsTest`

```
/**
 * Every state a user can be shown has real, distinct copy.
 *
 * Not an `ActivityScenario` walk: driving `SecuritySettingsActivity` through nine states needs
 * injection points that screen does not have, and this repository has no Activity-launching test to
 * build on. What *can* rot silently is a resource that was never added, a duplicate that makes two
 * different situations read identically, or a string that drifts into promising behaviour the app
 * does not have — and all three are caught here against a real Context.
 *
 * The mapping under test is the one the screens use; if a screen stops using it, that is visible in
 * review rather than here.
 */
```

### `fun noStringClaimsThisDeviceCanReadEncryptedMail()`

```
    /**
     * **The capability rule, enforced.** A user who completes this ceremony gets a device that HOLDS
     * a key it does not yet USE. Any string here claiming the user can read encrypted mail on this
     * device is false until the deferred decryption work lands.
     */
```

Replaced with: `/** The device HOLDS a key it does not yet USE, so no copy may promise reading mail here. */`

### `val banned = listOf(`

```
        // "use encrypted mail on this device" and not the shorter "use encrypted mail": the
        // account-level rows legitimately say "your account doesn't use encrypted mail yet", which
        // is a fact about the account and not a claim about what this device does. What is banned is
        // the device-scoped promise — security_encryption_no_lock_screen used to read "Set a screen
        // lock to use encrypted mail on this device", and a user who followed it through the whole
        // ceremony was then told "You'll still read your encrypted mail in your browser for now".
```

Replaced with: `// Device-scoped only: account rows may say "your account doesn't use encrypted mail yet".`

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentStateTest.kt

### `fun healthyLockedKeyReportsEnrolledWithoutAPrompt()`

```
    /**
     * The load-bearing case: a healthy, merely-locked key must report ENROLLED **without any user
     * authentication**, because this probe runs from a background worker where nothing can show a
     * prompt. If this fails, the spec's decision 4 needs revisiting before the reporting path is
     * trusted — see the note in this task.
     */
```

Replaced with: `/** The probe runs from a background worker, so it must report ENROLLED with no prompt. */`

### `fun regeneratingTheKeyDiscardsABlobItCannotOpen()`

```
    /**
     * The regression that matters: a fresh key must never coexist with a blob it cannot open.
     *
     * Cipher.init on GCM touches no ciphertext, so it succeeds against ANY key — the probe therefore
     * cannot tell "this key opens this blob" from "a key exists and a blob exists". Before the fix,
     * the OS destroying the vault key (which a user removing and re-adding their lock screen is
     * enough to do) followed by any re-seal left a new key beside the old blob, and the probe
     * reported ENROLLED for a device that could decrypt nothing. The server renders that to the user
     * as "this device can read your encrypted mail" — the exact lie the marker exists to prevent,
     * in the unsafe direction.
     */
```

Replaced with: `/** Cipher.init on GCM succeeds against any key, so a fresh key must never keep an old blob. */`

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentStateWorkerTest.kt

### `fun theRequestCarriesNoInputData()`

```
    /**
     * The load-bearing one. WorkManager writes a request's input data to its own database in
     * plaintext, so a credential carried there would sit on disk outside every store this app
     * encrypts. The worker reads it from `SecurePairingStore` at run time instead — which only
     * holds if the request genuinely carries nothing.
     */
```

Replaced with: `/** WorkManager stores input data in plaintext on disk, so the request must carry nothing. */`

## app/src/androidTest/java/org/kysecurity/mail/pgp/EnrollmentTeardownTest.kt

### `fun asecondPassOverNothingReportsSuccess()`

```
    /**
     * Teardown must be safe to run twice, because both callers can be interrupted and re-entered:
     * a process death mid-wipe, or Hostile Location Protection toggled again. A second pass over
     * nothing must report success, not a phantom failure that would mark the wipe incomplete.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/pgp/PgpFingerprintSubkeyDeviceTest.kt

### `class PgpFingerprintSubkeyDeviceTest`

```
/**
 * [PgpFingerprint.compute] on a key that actually has an encryption subkey, on a real device.
 *
 * Every other fixture is a bare primary key with no subkey at all, so `hasValidBindingSignature` —
 * which runs a real signature verification through the platform JCA — was never once executed by a
 * test. Real accounts' keys all carry an encryption subkey, so on a real device that verification
 * sits on the path deciding whether the Security page can name the account's key at all.
 */
```

Replaced with: `/** The only fixture with an encryption subkey, so binding-signature verification runs. */`

## app/src/androidTest/java/org/kysecurity/mail/pgp/PgpFingerprintSubkeyFixture.kt

### `internal object PgpFingerprintSubkeyFixture`

```
/**
 * ed25519 primary + cv25519 encryption subkey, from `gpg --quick-generate-key` plus
 * `--quick-add-key`. Disposable, generated in a throwaway keyring purely as a fixture.
 *
 * The shape matters: every other fixture in this repo is a bare primary key with no subkey, which
 * never exercises the binding-signature verification real accounts' keys all go through.
 * [FINGERPRINT] is gpg's own reported value for it.
 */
```

Replaced with: `/** Disposable ed25519 primary + cv25519 subkey from gpg; FINGERPRINT is gpg's own value. */`

## app/src/androidTest/java/org/kysecurity/mail/push/MfaChallengeTrackerPersistenceTest.kt

### `class MfaChallengeTrackerPersistenceTest`

```
/**
 * The tracker's storage half. It used to be a process-lifetime `ConcurrentHashMap`, which was
 * usually already gone by the time the user tapped the notification: FCM delivers to a
 * freshly-started process and Android kills it again moments later, so a legitimate tap fell
 * through to the inbox with no explanation while the sign-in timed out.
 */
```

Replaced with: `/** Persisted, not in-memory: the FCM process usually dies before the user taps. */`

### `fun aClearedChallengeIsNotResurrectedByAConcurrentDelivery()`

```
    /**
     * A concurrent delivery must not resurrect a challenge that was just cleared.
     *
     * [MfaChallengeTracker.markDelivered] is a read-modify-write that rebuilds the whole file from
     * a snapshot, and [MfaChallengeTracker.clear] removes one key. Unserialised, a `clear` landing
     * between another thread's read and its rewrite was silently undone — which resurrects a
     * challenge the user burned by mis-tapping the number, or one the server has already accepted
     * an answer for, breaking "answered once, answerable once". It fires exactly during a challenge
     * flood, i.e. during the MFA-fatigue attack the whole feature resists.
     */
```

Replaced with: `/** markDelivered rebuilds the whole file, so an unserialised clear can be silently undone. */`

### `fun theAlertCooldownSurvivesANewTrackerInstanceAndOtherDeliveries()`

```
    /**
     * The alert cooldown shares this file so it survives process death — the reason the challenge
     * records are persisted in the first place. Held in a process-scoped `var`, it reset on every
     * FCM-driven process churn, so under a real flood every challenge alerted at IMPORTANCE_HIGH.
     */
```

Replaced with: `/** The cooldown shares this file so it survives the FCM-driven process churn. */`

### `fun restoringTheCooldownReopensTheAlertWindow()`

```
    /**
     * A delivery that posted no notification must not spend the cooldown, or a single revoked
     * POST_NOTIFICATIONS (or a SecurityException on the way out) silences the next five minutes of
     * sign-in prompts the user *would* have seen.
     */
```

## app/src/androidTest/java/org/kysecurity/mail/push/NotificationIntentTokenTest.kt

### `class NotificationIntentTokenTest`

```
/**
 * MainActivity is exported, so every extra on an inbound Intent is reachable by any co-installed
 * app with no permissions at all. This is what tells one of its own PendingIntents apart from a
 * forgery.
 */
```

Replaced with: `/** MainActivity is exported, so extras are forgeable; this token proves our own PendingIntent. */`

## app/src/androidTest/java/org/kysecurity/mail/push/UnpairEnrollmentTeardownTest.kt

### `class UnpairEnrollmentTeardownTest`

```
/**
 * Leaving an account must destroy that account's sealed envelope.
 *
 * The security wipe and Hostile Location Protection both tear the enrollment down. The account
 * boundary — the one an exported `kypost://native-pair` deep link can drive behind a single
 * confirmation tap — did not, so one account's PGP private key persisted into the next account's
 * session on the same device, under a key that only needs the device lock screen to open.
 */
```

Replaced with: `/** Unpairing must destroy the envelope, or one account's key persists into the next session. */`

## app/src/androidTest/java/org/kysecurity/mail/push/SecurePairingStoreCredentialGateTest.kt

### `fun clearAnyExistingState()`

```
        // CredentialCipher.deriveKeys reads the pepper and never creates it — the split that stopped
        // a lost verifier key from reading every correct PIN as wrong and wiping the device on the
        // tenth try. Production creates it on the establish path (AppLockManager, PinHasher); these
        // tests derive keys directly, so on a device that has never set a PIN there is no pepper to
        // read. Without this they pass only where an earlier test happened to establish one.
```

Replaced with: `// deriveKeys only reads the pepper — nothing here would create it, so establish it first.`

### `fun savePairing_withSecretWritePreserve_leavesAWrappedSecretIntact()`

```
    /**
     * The regression that made a background token rotation unrecoverable.
     *
     * `PushRepository.savePairing` reaches this when the credential gate is on and no PIN-derived
     * key is cached. It passes `deviceSecret = null` to mean "I may not persist this one", and the
     * store used to read that as "there is no secret" and erase the stored one — while the server
     * had just minted a replacement and revoked the old. The device was left with no credential at
     * all and no repair path: a rewrap has nothing to rewrap, and turning the gate off unwraps a
     * value that is no longer there.
     */
```

Replaced with: `/** deviceSecret = null used to erase the stored secret, leaving a rotated device with none. */`

## app/src/androidTest/java/org/kysecurity/mail/push/SecurePairingStoreTest.kt

### `fun tlsPinCache_tracksEveryWriteAndSurvivesReload()`

```
    /**
     * The in-memory pin cache must stay in step with the file. This was a paragraph of KDoc
     * asserting that [SecurePairingStore.saveTlsPin] and [SecurePairingStore.clearPairing] are the
     * only writers and both update it; prose does not fail the build.
     */
```

### `fun corruptedKeyset_doesNotCrash_resetsToUnpairedAndStaysUsable()`

```
    /**
     * Regression test for a real production crash: the Keystore-backed key can stop being able to
     * decrypt the on-disk Tink keyset (observed as `AEADBadTagException` from
     * `EncryptedSharedPreferences.create`), which happens inside [SecurePairingStore]'s init path —
     * uncaught, that crashed the app on every single launch. Simulates the same failure mode by
     * corrupting the on-disk keyset directly (flipping its ciphertext/tag rather than waiting for a
     * real Keystore invalidation event, which isn't triggerable on demand) and asserts the store
     * recovers instead of throwing: it must report `pairing == null` and still be fully usable
     * afterward, matching [buildEncryptedPrefs]'s wipe-and-recreate fallback.
     */
```

Replaced with: `/** A corrupt keyset makes EncryptedSharedPreferences.create throw in init; it must recover. */`

## app/src/androidTest/java/org/kysecurity/mail/ui/InboxRailTest.kt

### `class InboxRailTest`

```
/**
 * The bool resource and the layout resolve through the same qualifier, so they can never disagree.
 * This asserts exactly that pairing: wherever nav_is_rail is true a NavigationRailView was
 * inflated, and wherever it is false one was not. It therefore passes on a phone and on a tablet
 * without the test knowing which it is running on.
 */
```

Replaced with: `/** nav_is_rail and the layout share a qualifier, so this passes on both phone and tablet. */`

## app/src/androidTest/java/org/kysecurity/mail/ui/InboxStateRestoreTest.kt

### `fun rememberTheKeywordTheTabNames()`

```
    /**
     * The restored tab only survives if a chip for it still exists after the recreate, and
     * `rebuildTabs` builds those chips from [KeywordSettings], not from the current email batch
     * (`InboxActivity.kt:470-481`). A tab naming a keyword the app has never seen is correctly
     * reset to All — so a test that sets one through a seam without registering it is asserting a
     * promise production does not make, and it fails for that reason rather than a broken restore.
     *
     * On a real device the keyword is already remembered, because the only way to select the chip
     * is for the chip to exist. Registering it here reproduces that precondition instead of
     * weakening the assertion.
     */
```

Replaced with: `/** rebuildTabs builds chips from KeywordSettings, so the tab's keyword must be registered. */`

### `fun forgetTheKeyword()`

```
    /**
     * Keyword storage is SharedPreferences-backed and process-wide, and [KeywordSettings] exposes
     * no removal API — so hiding is the supported way to stop an invented keyword becoming a chip
     * in every later test class. `rebuildTabs` builds its chips from `filterVisible`, so a hidden
     * keyword contributes nothing.
     */
```

Replaced with: `/** KeywordSettings has no removal API, so hide it to keep it out of later test classes. */`

### `fun pendingScrollPositionIsNotConsumedByAnEmptyRenderAfterRecreate()`

```
    /**
     * `refreshInbox()`'s async fetch has not populated the adapter yet when `onResume()` runs
     * `renderFilteredEmails()` right after a recreate, so the list is empty at that moment. A
     * saved scroll target must survive that empty render, or it is lost before the data (and the
     * position it was meant to restore) ever arrives. This environment has no network/cache data,
     * so the adapter is guaranteed empty here -- reproducing exactly that window without needing a
     * populated list.
     */
```

Replaced with: `/** The adapter is still empty after recreate; the saved scroll target must survive that render. */`

## app/src/androidTest/java/org/kysecurity/mail/security/AuthGateKeyTest.kt

### `class AuthGateKeyTest`

```
/**
 * The gate the MFA approval screen falls back to when nothing is sealed.
 *
 * The success path needs a live prompt and no automated test can produce one, so what is pinned
 * here is the property the gate rests on: without the user, the key does not work. If that ever
 * stops being true the screen is back to trusting a callback.
 */
```

Replaced with: `/** The success path needs a live prompt; what is pinned here is that the key fails without one. */`

### `assertTrue("a per-use key must have no validity window, ...")`

```
        // What matters is that there is no time window in which one earlier unlock keeps paying for
        // later operations. The two Keystore APIs spell "authenticate for every use" differently:
        // the legacy setUserAuthenticationValidityDurationSeconds uses -1, while
        // setUserAuthenticationParameters — the only one this codebase calls, and the only one
        // available at minSdk 31 — uses 0, which is what KeyInfo then reports back. Pinning -1 here
        // pinned the sentinel of an API AuthGateKey never uses. Any POSITIVE value is the real
        // regression, so that is what this rules out.
```

Replaced with: `// Per-use reports 0 here, not the legacy -1 sentinel; any positive value is the regression.`

## app/src/androidTest/java/org/kysecurity/mail/security/CredentialCipherKeystoreTest.kt

### `class CredentialCipherKeystoreTest`

```
/**
 * Exercises the real [KeystoreCredentialPepper] — the unit tests substitute a fixed pepper because
 * a JVM test has no AndroidKeyStore, so this is the only place the actual device binding is
 * verified.
 */
```

Replaced with: `/** The only place the real KeystoreCredentialPepper device binding is exercised. */`

### `fun establishThePepper()`

```
    /**
     * [KeystoreCredentialPepper.mix] reads the pepper and never creates it — the split that stopped
     * a lost verifier key from reading every correct PIN as wrong and wiping the device on the tenth
     * try. Production creates it on the establish path ([AppLockManager.deriveUsingPersistedSalt],
     * [PinHasher.hash]); a test that only ever reads must do the same, or it passes solely on a
     * device where some earlier test happened to establish one.
     */
```

Replaced with: `/** mix only reads the pepper; production creates it on the establish path, so create it here. */`

## app/src/androidTest/java/org/kysecurity/mail/security/EphemeralAttachmentProviderTest.kt

### `fun clearingProcessScopedState_dropsAndZeroesHeldPlaintext()`

```
    /**
     * The wipe path, which this holder was invisible to.
     *
     * [EphemeralAttachmentBytes] parks up to [org.kysecurity.mail.MemoryBudget.PENDING_ATTACHMENT_BYTES]
     * of decrypted attachment plaintext in a
     * process-scoped object, and `AppRestart.relaunch` no longer kills the process — so a security
     * wipe used to run to completion, relaunch into the same JVM and leave every registered
     * attachment readable in the attacker's session. It was never added to `InMemoryPlaintext`,
     * whose KDoc had explicitly invited exactly this kind of holder to register.
     */
```

Replaced with: `/** AppRestart.relaunch no longer kills the process, so held plaintext must be cleared. */`

### `val expected = bytes.copyOf()` in `fun register_thenRead_roundTripsBytesAndMimeType()`

```
        // Snapshot the expectation BEFORE registering. register() retains this exact array and the
        // provider zeroes it once the pipe has been written, which is the whole point — plaintext
        // must not linger in the heap. Comparing against the original reference was therefore a
        // race: whether it passed depended on whether the writer thread's zeroing had run yet.
```

Replaced with: `// Snapshot before registering: register() retains this array and the provider zeroes it.`

### `fun register_refusesOnceTheHeldPlaintextCeilingIsReached()`

```
    /**
     * The held-plaintext ceiling. MAX_CONCURRENT_WRITES bounded writer *threads*; nothing bounded
     * the map, so tapping attachments and backing out of each chooser — which never calls `take` —
     * accumulated decrypted mail in the heap until the process died, on the one path whose premise
     * is that this plaintext is short-lived.
     */
```

Replaced with: `/** Nothing bounded the map, so backing out of choosers accumulated decrypted mail in the heap. */`

### `val each = (MemoryBudget.PENDING_ATTACHMENT_BYTES * 2 / 3).toInt()`

```
        // Sized FROM the ceiling, not against a literal. This read "two 40 MB registrations exceed
        // the 64 MB ceiling" and broke the moment the ceiling moved to 32 MB — the first
        // registration was refused and `requireNotNull` threw, reporting the ceiling working as a
        // test failure. The property is "two that individually fit but together do not"; two-thirds
        // each expresses that at any ceiling.
```

Replaced with: `// Sized from the ceiling, not a literal: two that individually fit but together do not.`

## app/src/androidTest/java/org/kysecurity/mail/security/HostileLocationEnrollmentTeardownTest.kt

### `class HostileLocationEnrollmentTeardownTest`

```
/**
 * Hostile Location Protection destroys the enrollment but deliberately keeps the device paired.
 *
 * Those two facts pull in opposite directions, which is why they are asserted together: an envelope
 * surviving the toggle leaves the account's private key openable by device unlock on a device whose
 * owner has just declared they are somewhere hostile, while unpairing would silently break push and
 * sync for a mode that is documented to keep both working.
 */
```

Replaced with: `/** HLP destroys the enrollment but must keep the device paired; both are asserted here. */`

## app/src/androidTest/java/org/kysecurity/mail/security/AbandonedWipeBlocksBackgroundWorkTest.kt

### `class AbandonedWipeBlocksBackgroundWorkTest`

```
/**
 * [SecurityWipe.blockedByAbandonedWipe] and the background entry points that depend on it.
 *
 * [LockedActivity]'s terminal block covers Activities, and only Activities. It was the whole
 * enforcement of the abandoned-wipe state, which left the paths that need no screen wide open —
 * and those are the ones that matter most, because an abandoned wipe very often leaves the pairing
 * credential on disk (`sharedPrefs` is the step that holds it, and one of the likelier ones to
 * fail). Push kept arriving, the pull worker kept fetching mail metadata and rendering sender and
 * subject as notifications, the contact worker kept writing the account's contacts back into the
 * OS provider, and a token refresh would have minted a **fresh** device secret — re-arming exactly
 * the access the wipe was trying to revoke.
 *
 * These assert the guard flips correctly and that the workers act on it. The push services take
 * the same guard on their first line; there is no way to deliver a real `RemoteMessage` from a
 * test, so those are covered by the shared predicate here rather than end to end.
 */
```

Replaced with: `/** The abandoned-wipe guard on the paths with no screen; LockedActivity only covers Activities. */`

### `private fun markAbandoned()`

```
    /**
     * Puts the app in the terminal state directly rather than by failing three real wipes, which
     * would take minutes and destroy unrelated fixtures.
     *
     * The keys mirror `SecurityWipe`'s private constants, so this could rot into writing
     * meaningless preferences that leave the guard false and pass every assertion below for the
     * wrong reason. That is what the precondition in each test is for: it asserts the *production*
     * predicate agrees, so a rename fails here loudly instead of silently disarming the suite.
     */
```

Replaced with: `/** Keys mirror SecurityWipe's private constants; each test's precondition catches a rename. */`

### `fun pullWorker_cancelsItselfInsteadOfPolling()`

```
    /**
     * The pull worker is what turns a surviving credential into live mail metadata on the lock
     * screen. Cancelling, not merely skipping: the periodic work is already enqueued, and nothing
     * in a blocked app will legitimately want it back before a reinstall.
     */
```

Replaced with: `/** Cancels rather than skips: the periodic work is already enqueued and must not fire again. */`

### `fun deviceContactSyncWorker_cancelsItselfInsteadOfWritingContacts()`

```
    /**
     * The contact worker writes to the OS contacts provider — outside this app's sandbox, where no
     * sandbox deletion reaches. Re-populating it after a failed wipe undoes the one step of the
     * wipe the user cannot clean up themselves by uninstalling.
     */
```

Replaced with: `/** The contacts provider is outside the sandbox, where no sandbox deletion reaches. */`

## app/src/androidTest/java/org/kysecurity/mail/security/BiometricUnlockVaultTest.kt

### `class BiometricUnlockVaultTest`

```
/**
 * The Keystore half of biometric unlock.
 *
 * The open path cannot be driven to completion here — the private key needs a live
 * `BiometricPrompt`, which no automated test can satisfy — so the crypto itself is pinned in
 * `CredentialEnvelopeTest` and what this suite proves is everything around it: that the key really
 * does refuse to work without the user, and that a device with no biometric seals nothing rather
 * than sealing under something weaker.
 */
```

Replaced with: `/** The open path needs a live prompt; the crypto is pinned in CredentialEnvelopeTest. */`

### `fun theSealingKeyRequiresUserAuthentication()`

```
    /**
     * The property everything else rests on. A key that could be used without the user would make
     * the sealed blob openable by anyone holding a device image, which is the whole of what the
     * fingerprint is buying.
     */
```

### `fun withNoEnrolledBiometricNothingIsSealed()`

```
    /**
     * Fail closed on a device with no fingerprint: no key, no blob, and no biometric offer. The
     * unsafe alternative is a key minted under whatever authenticators *are* available, which would
     * quietly turn the device lock-screen PIN into a way past this app's own PIN.
     */
```

Replaced with: `/** Fail closed: a key under whatever authenticators exist would let the device PIN past ours. */`

## app/src/androidTest/java/org/kysecurity/mail/security/HostileLocationSettingsTest.kt

### `class HostileLocationSettingsTest`

```
/**
 * The flag that decides whether the user's mail exists on disk at all.
 *
 * This suite used to assert two things — the default is false, and it persists — because there was
 * nothing else to assert: the setting was a bare `Boolean` in a `MODE_PRIVATE` preferences file,
 * the exact primitive [KeystoreTripwireKey]'s KDoc spends a paragraph proving is not a control. The
 * app-lock tripwire got a Keystore anchor over a much smaller claim. This one had none, so an
 * attacker who could write the app sandbox could turn protection off and the next process start
 * would quietly begin writing decrypted mail to disk for a user who had chosen the mode precisely
 * so that no file would exist.
 *
 * The tamper tests below are the ones that matter, and none of them could have been written before.
 */
```

Replaced with: `/** The Keystore anchor is what stops a sandbox writer downgrading protection silently. */`

### `DataRuntime.invalidate()` in `fun resetState()`

```
        // The tamper tests below leave the posture reading ENABLED for the length of a method, and
        // DataRuntime is a process-lifetime singleton that caches whichever shape of DataGraph was
        // built first — in-memory under protection, disk-backed without it. A neighbouring class
        // that asks for an on-disk database would otherwise inherit an in-memory one and fail on a
        // precondition it never set. Dropping the holder is what AppRestart.relaunch does in
        // production after every real toggle; this class has to do it by hand because it fakes
        // postures the production toggle never produces.
```

Replaced with: `// Tamper tests leave the posture ENABLED; drop the cached graph a neighbour would inherit.`

### section banner above `fun forgingTheFlagToFalseDoesNotTurnProtectionOff()`

```
    // --- Tampering. Each of these was a silent, successful downgrade before the anchor existed. ---
```

### `fun aForgedEnabledFlagOnAFreshInstallIsNotHonoured()`

```
        // The mirror-image weaponisation, and the reason "no key means DISABLED" must come before
        // the marker is read at all: writing `enabled=true` onto a device that never enabled
        // protection would otherwise make the app present an empty mailbox as if it were the
        // user's, on first launch, forever.
```

Replaced with: `// The mirror image: a forged enabled=true would present an empty mailbox as the user's.`

## app/src/androidTest/java/org/kysecurity/mail/security/AppLockStoreTest.kt

### `store.reset()` in `fun tripwire_recordsThatALockExisted_andClearsWhenTheLockIsTurnedOff()`

```
        // reset() is the disarm path — the one "Require Unlock to Open" actually calls, and now the
        // only one. `setLockEnabled(false)` used to exist alongside it, had no production caller,
        // and threw PepperUnavailableException on a device that had never armed the lock, because
        // it wrote a marker authenticated by a key it then destroyed.
```

Replaced with: `// reset() is the disarm path "Require Unlock to Open" calls, and now the only one.`

### `fun tripwire_trips_whenBothPreferenceFilesAreDeleted()`

```
    /**
     * The bypass the plain-file tripwire did not close.
     *
     * As an unauthenticated `MODE_PRIVATE` file, the marker was defeated by deleting *two* files
     * instead of one: with `app_lock_tripwire.xml` gone alongside `app_lock_secure.xml`,
     * `wasLockEnabled()` read false and the lock was simply gone, with no wipe. The durable half of
     * the marker is now a Keystore alias, which writing to the app sandbox cannot remove.
     */
```

Replaced with: `/** Deleting both prefs files used to erase the lock silently; a Keystore alias now survives it. */`

### `fun tripwire_doesNotFireOnAForgedMarkerWhenNoLockWasEverConfigured()`

```
    /**
     * The other direction, which the plain file made possible: anything that could write the app
     * sandbox could forge `lock_was_enabled=true` on a device that never had a lock and make the
     * next launch destroy the user's mail. The marker is now HMACed under a Keystore key, so a
     * forged value does not authenticate.
     *
     * The assertion is deliberately about `tripwireBroken()`, not `wasLockEnabled()`: a forged
     * marker reads as tampering either way, but on a store that never had a lock there is nothing
     * to protect and nothing to destroy.
     */
```

Replaced with: `/** A forged marker on a store that never had a lock has nothing to protect, so no wipe. */`

### `fun credentialSalt_refusesToOverwrite_loudly()`

```
    /**
     * The salt guard used to log and return, telling the caller a salt had been persisted when it
     * had not — after which the device secret was wrapped under a key nothing would reproduce.
     */
```

Replaced with: `/** A silent salt overwrite left the device secret wrapped under a key nothing reproduces. */`

## app/src/androidTest/java/org/kysecurity/mail/security/SecurityWipeTest.kt

### `fun resetWipeState()`

```
    /**
     * The resume-attempt counter is deliberately sticky in production — clearing it along with the
     * in-progress flag is what made MAX_WIPE_RESUMES a rolling window that bounded nothing — so it
     * survives between tests in this class and has to be reset explicitly. Without this, whichever
     * test ran fourth would hit the ceiling and see the marker cleared.
     */
```

Replaced with: `/** The resume counter is deliberately sticky in production, so reset it between tests. */`

### `fun wipeAndResetApp_removesPushHistoryFromDisk()`

```
    /**
     * The wipe used to stop at the database, the pairing prefs and the app lock — leaving the last
     * 30 push payloads, i.e. sender names and email subjects, sitting in the unencrypted
     * `push_state` DataStore. A wipe that runs *because* the device is presumed hostile cannot
     * leave the message metadata behind.
     */
```

Replaced with: `/** push_state holds sender names and subjects in the clear; a wipe cannot leave it behind. */`

### `fun wipeAndResetApp_reportsIncomplete_whenAStepFails()`

```
    /**
     * The wipe must not claim Complete when a step really failed.
     *
     * `SecurityWipe`'s own KDoc says it "must never report [WipeResult.Complete] unless every step
     * really ran", and three steps could not fail at all: `deviceContacts`, `deregister` and
     * `clearPairingState` each delegated to helpers whose every statement sat in its own
     * `runCatching { }.onFailure { Log }`. The one that mattered most deletes the user's contacts
     * out of the OS provider — outside this app's sandbox — and a failure there was reported as a
     * clean wipe.
     *
     * Provoked through the shared-prefs enumeration, which is the step whose precondition a test
     * can actually remove: with `shared_prefs` made unreadable there is no way to enumerate what
     * needs deleting, and "I cannot see what to delete" must not read as "there was nothing".
     */
```

Replaced with: `/** Provoked through shared_prefs: "cannot enumerate what to delete" must not read as Complete. */`

### `fun anIncompleteWipe_stopsResumingAfterTheCeiling_butStaysOnRecord()`

```
    /**
     * An incomplete wipe must stop resuming eventually.
     *
     * The marker used to be cleared only on a fully clean run, with no ceiling — so a permanently
     * failing step meant the app wiped itself at every launch, forever, with no way for the user to
     * get past it. `clearWebViewState` recursively deleted `cacheDir` in a live process where
     * OkHttp, WebView and ART were still creating files inside it; losing that race is routine.
     *
     * The first fix overcorrected in the other direction: it expressed "stop resuming" by clearing
     * the marker, which threw away the record that data was still on disk. Stopping the retries and
     * forgetting the failure are separate things, and this asserts both halves — no resume, and no
     * forgetting. See [WipeResurrectionTest.pastTheCeiling_theIncompleteStateIsPermanentAndNotForgotten].
     */
```

Replaced with: `/** Stopping the retries and forgetting the failure are separate; both halves are asserted. */`

### `fun wipeAndResetApp_removesTheUnifiedPushConnectorStore_evenWithNoReachableServer()`

```
    /**
     * Local push teardown must not sit behind the network call.
     *
     * The connector's SQLite database holds the WebPush ECDH private key and auth secret. It used
     * to be deleted *after* the server deregister, inside a `withTimeoutOrNull(3s)` whose bound was
     * set to exactly the deregister client's own 3s `callTimeout` — so the two raced, and an
     * unreachable server (airplane mode: one swipe, before burning ten PINs) reliably cancelled the
     * coroutine before any of it ran. This test has no server at all, which is the failing case.
     */
```

Replaced with: `/** The connector DB holds the WebPush private key; its deletion must not sit behind the network. */`

## app/src/androidTest/java/org/kysecurity/mail/security/WipeResurrectionTest.kt

### `class WipeResurrectionTest`

```
/**
 * Regression tests for [SecurityWipe]'s ordering and its resume bookkeeping.
 *
 * Each of these began as an audit probe asserting a defect; they now assert the contract the fixes
 * established. The wipe runs precisely when the device is presumed hostile, so "what is still on
 * disk afterwards" and "what the app then tells the user" are both security properties.
 */
```

### `fun wipe_doesNotRecreateTheDatabaseFileItDeleted()`

```
    /**
     * The wipe deletes `kypost_mail.db` early and must not rebuild it later.
     *
     * `clearPairingState` -> `purgeAccountScopedData` used to dereference `DataRuntime.graph(...)`,
     * which constructs a Room database — fifteen steps after the one that deleted it. It now reads
     * through `peekGraph()`, so an already-torn-down graph means nothing to purge.
     */
```

Replaced with: `/** purgeAccountScopedData must peek the graph, not construct one after the delete step. */`

### `fun wipe_underHostileLocation_leavesNoDatabaseOnDisk()`

```
    /**
     * The same rebuild under Hostile Location Protection was worse: the flag deciding disk-vs-memory
     * had already been deleted by the `sharedPrefs` step, so the resurrected graph was DISK-backed —
     * a KyPost mail schema materialising on disk in the one mode that promises none.
     */
```

Replaced with: `/** Under HLP the resurrected graph was disk-backed, since the flag file was already deleted. */`

### `fun resumedWipe_restoresHostileLocationProtection()`

```
    /**
     * A wipe force-stopped after `step("sharedPrefs")` leaves the protection flag file deleted and
     * the resume marker set. The resumed run must still restore the posture.
     *
     * It used to re-read the flag from the file the interrupted run had already deleted, get
     * `false`, and skip the restore permanently — so the user re-paired onto a disk-backed plaintext
     * database on a device the app had just decided was hostile. The posture is now recorded in the
     * retained `wipe_state` file at `markWipeInProgress` time.
     */
```

Replaced with: `/** The posture is recorded in wipe_state, since the resumed run cannot re-read the deleted file. */`

### `fun wipeAttemptCeiling_climbsWhileResuming_thenResetsForTheNextWipe()`

```
    /**
     * `MAX_WIPE_RESUMES` bounds ONE wipe's resumes. It is not a rolling window, and it is not a
     * lifetime budget either.
     *
     * Two bugs have lived here. First, `clearWipeMarker()` used to `clear()` the whole file, dropping
     * the attempt counter with the in-progress flag, so reaching the ceiling reset the budget and the
     * counter cycled 1, 2, 0, 1, 2, 0 forever — the ceiling bounded nothing. The fix for that kept the
     * counter across the marker, which overshot: nothing reset it *ever*, so it became a per-install
     * lifetime budget. Wipes are reachable by ordinary user action — turning off "Require Unlock to
     * Open" with the credential gate on runs a full wipe — so three of those exhausted the budget,
     * and the wipe that actually matters (a thief burning PIN attempts) then got zero retries and
     * abandoned itself on its first failed step.
     *
     * The counter is now scoped to a wipe *episode*: `markWipeInProgress` starts it at 1 when the
     * marker was clear, and increments only when resuming a marker that is already set.
     */
```

Replaced with: `/** The counter is scoped to one wipe episode: not a rolling window, not a lifetime budget. */`

### `fun pastTheCeiling_theResultReportsThatNoRetryIsComing()`

```
    /**
     * Past the ceiling the wipe stops resuming, and says so: `willRetry` is what stops the UI
     * promising a retry on the one run that gave up.
     */
```

Replaced with: `/** willRetry is what stops the UI promising a retry on the run that gave up. */`

### `fun pastTheCeiling_theIncompleteStateIsPermanentAndNotForgotten()`

```
    /**
     * Giving up on the retries must not mean forgetting that deletion failed.
     *
     * The run that hit the ceiling used to call `clearWipeMarker()`, which is how "stop resuming"
     * was expressed — and it discarded the only durable evidence that data may still be on disk.
     * `wipeInterrupted` answered false from then on, the "some data may still be on this device"
     * notice was shown exactly once and never again, and every later launch presented a clean
     * first-run app over plaintext mail, contacts or attachments that were never deleted.
     *
     * Fail closed instead: the marker and the failed step names persist, and `enforceTripwire`
     * returns the same terminal `Incomplete(willRetry = false)` on every launch — which
     * [LockedActivity] blocks the whole app behind — without re-running the destructive pass.
     */
```

Replaced with: `/** Giving up on retries must not forget that deletion failed; the marker and steps persist. */`

### `fun wipe_keepsTheAttachmentLedgerWhenItsStepFailed()`

```
    /**
     * A wipe that promises a retry must leave the retry something to do.
     *
     * `step("downloadedAttachments")` keeps the URIs it could not delete and throws, producing
     * `Incomplete(willRetry = true)` and the notice "it will be retried when the app next starts".
     * But `step("sharedPrefs")` runs eleven steps later and used to delete the ledger file along
     * with everything else, so the resumed wipe read an empty set, passed the step, and reported
     * **Complete** — telling the user their local data was erased while the attachment plaintext
     * was still sitting in shared Downloads.
     *
     * The undeletable entry is a `content://` URI with an authority no provider claims, so
     * `ContentResolver.delete` throws. That is the same shape as the real case the ledger was
     * hardened for: a MediaStore row this package created and can no longer touch.
     */
```

Replaced with: `/** The ledger must survive the sharedPrefs sweep, or a promised retry has nothing to retry. */`

### `fun wipe_destroysTheDeviceEnrollment()`

```
    /**
     * A wipe reached by ten wrong PINs must not leave behind the keys that open this device's
     * envelope. Surviving them would outlive a wipe nobody chose, and the vault key is openable by
     * nothing more than the device unlock.
     *
     * Asserted through the real `wipeAndResetApp`, not the teardown helper, because the ordering is
     * the risk: the sharedPrefs sweep runs after this step and would recreate the vault's file if
     * the step ran too late.
     */
```

Replaced with: `/** Through the real wipeAndResetApp: ordering is the risk, sharedPrefs sweeps after this step. */`

## app/src/androidTest/java/org/kysecurity/mail/security/FoldLockBehaviourTest.kt

### file header, above `@file:Suppress("DEPRECATION")`

```
// androidx.security-crypto is deprecated in full with no replacement API; [AppLockSnapshot] below
// has to speak the same at-rest format AppLockStore does, so it carries the same suppression the
// production file carries.
```

Replaced with: `// androidx.security-crypto is deprecated with no replacement; AppLockSnapshot mirrors AppLockStore.`

### `class FoldLockBehaviourTest`

```
/**
 * The three halves of the foldable lock contract. A live resize must not lock; a close-and-lock
 * must; and, unique to this feature, two embedded panes locking at once must still collapse into
 * one unlock prompt. None is assumed anywhere in this feature — all three are asserted here.
 *
 * **These tests only mean anything with the app lock enabled and a PIN configured**, which is not
 * the shipped default ([AppLockStore.isLockEnabled] returns false on a clean install). Without the
 * setup below, [AppLockManager.lockNow] does not set the locked flag at all: the two locking tests
 * fail, and the resize test passes vacuously because nothing could have locked it in the first
 * place.
 *
 * **No [androidx.test.core.app.ActivityScenario] anywhere in this class.** Every screen here is a
 * [LockedActivity], and a [LockedActivity] under a lock `finish()`es itself from `onCreate`
 * ([LockedActivity.redirectToUnlockIfLocked]) — which is precisely the property being asserted.
 * `ActivityScenario.recreate()` blocks until the recreated Activity reaches `RESUMED` and
 * `onActivity {}` requires a live instance, so both fail on the Activity they are meant to observe:
 * the gate that works reads as "Activity never becomes requested state [RESUMED]". An
 * [Instrumentation.ActivityMonitor] can observe an Activity that finishes itself during startup,
 * so the launches, the recreates and the redirect are all driven and observed through monitors and
 * a process-wide [Application.ActivityLifecycleCallbacks] instead.
 *
 * **This class must never be able to trigger [SecurityWipe].** A test that can wipe the app under
 * test destroys the mail cache, the pairing, the PGP key envelope and the app-lock config on
 * whatever device it runs on. Exactly one PIN attempt is made per test — in [enableTheAppLock],
 * with the PIN written on the line above it — so the failed-attempt count this class can contribute
 * is provably at most one against a [LockoutPolicy.WIPE_THRESHOLD] of ten, and
 * [restoreTheAppLockStateAsFound] puts the stored counter back where it found it either way.
 * Nothing here calls [AppLockStore.reset]: see [AppLockSnapshot].
 */
```

Replaced with: `/** Never let this class reach LockoutPolicy.WIPE_THRESHOLD: at most one PIN attempt per test. */`
(The "no ActivityScenario" reason survives in the surviving KDoc on `awaitCreated`.)

### `fun restoreTheAppLockStateAsFound()`

```
    /**
     * Hands the process back exactly as it was found, on every exit path including an assertion
     * failure — JUnit runs this whatever the test body did.
     *
     * Ordering is the point, and each step is here because leaving it out cascade-fails a later
     * class rather than this one:
     *
     * 1. Every Activity this class started is finished first. A [UnlockActivity] left alive is
     *    `singleInstance`, so the next test's first redirect would land on it as `onNewIntent` and
     *    the "exactly one prompt" count would read zero.
     * 2. The app-lock files are restored from [AppLockSnapshot] rather than cleared. `reset()`
     *    would leave the next class with no PIN, no lock and — worse on a real device — no
     *    credential salt, which makes an already-wrapped `deviceSecret` undecryptable.
     * 3. The graphs that cache a DAO handle are dropped. This class is the first in the run to
     *    launch [InboxActivity], so it is the first to build [org.kysecurity.mail.mail.MailGraph],
     *    which captures `DataRuntime.graph(...).database.emailDao()` at construction. `SecurityWipeTest`
     *    and `WipeResurrectionTest` run later in this same package and close that database
     *    ([SecurityWipe.closeAndDeleteDatabase]) without the [AppRestart] relaunch production always
     *    performs — so the handle cached here is what `InboxRailTest` later reads through, and
     *    "connection is closed" on a background executor thread is an uncaught exception, i.e. a
     *    process kill. [org.kysecurity.mail.data.DataRuntime] is deliberately NOT invalidated: it
     *    owns the open database, and dropping it without closing it would orphan a second live
     *    handle on `kypost_mail.db` and make the later wipes fail to delete the file.
     * 4. [SecurityRuntime] goes too, so the next [AppLockManager] seeds `_locked` from the restored
     *    state instead of carrying this class's in-memory unlock.
     */
```

Replaced with: `/** DataRuntime is deliberately NOT invalidated: it owns the open DB and would orphan a handle. */`

### `fun lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt()`

```
    /**
     * Before Activity Embedding, two [LockedActivity] instances could never be visible at once —
     * this test's whole premise is a code path that has never existed in this app until this
     * feature. [InboxActivity] as the primary pane and [EmailDetailActivity] as the secondary
     * stand in for a split; locking both, independently, each redirects to [UnlockActivity] and
     * `finish()`es itself ([LockedActivity.redirectToUnlockIfLocked]). [UnlockActivity] is
     * `android:launchMode="singleInstance"` (`AndroidManifest.xml`, around `:186`), so the second
     * `startActivity` call is contractually required to resolve against the instance the first
     * call created rather than starting a new one — that collapse, not merely "both panes gate",
     * is the property this test exists for.
     *
     * [Application.ActivityLifecycleCallbacks] observes `onActivityCreated` process-wide, which is
     * the one signal that distinguishes "the second call was routed to the existing singleInstance"
     * from "the second call created a stacked second prompt": `singleInstance` delivery to an
     * existing instance is [Activity.onNewIntent], not a fresh `onCreate`. This is a direct
     * assertion of the launch-mode contract, not a proxy for it.
     *
     * The two panes are gated one at a time, and deliberately by different halves of the gate. A CI
     * emulator has no real split, so only the top pane is ever `RESUMED` — and `Activity.recreate()`
     * on a stopped Activity is documented to defer until it is next visited, which would make a
     * "recreate both" version of this test assert nothing about the primary. So the secondary is
     * driven through [Activity.recreate] (the configuration change a fold produces, gated in
     * `onCreate`) and the primary by being started again (gated in `onStart`; see
     * [LockedActivity.onStart], "the app can lock while this screen sits in the back stack"). Both
     * are real, independent `startActivity(UnlockActivity)` calls from [LockedActivity], which is
     * all the collapse assertion needs.
     */
```

Replaced with: `/** The emulator has no real split, so the primary is re-started (onStart gate), not recreated. */`

### section banner above `startPane`

```
    // ---- Activity plumbing -------------------------------------------------------------------
```

### `private fun <T : Activity> awaitCreated(...)`

```
    /**
     * Runs [trigger] with a monitor already registered for [cls] and returns the instance it
     * created, or null if none was within [timeoutMs].
     *
     * The monitor goes up first because a gated screen redirects and finishes from inside
     * `onCreate`; anything that looks for it afterwards is looking for an Activity that is
     * already gone.
     */
```

Replaced with: `/** The monitor goes up first: a gated screen redirects and finishes from inside onCreate. */`

### `private fun finishEveryActivityStartedHere()`

```
    /**
     * Leaves no Activity of this class's making behind, however the test exited.
     *
     * Loops rather than sweeping once: finishing a gated pane can itself start a [UnlockActivity]
     * that was not in the first snapshot, and that is exactly the instance whose survival would
     * absorb the next test's first redirect.
     */
```

Replaced with: `/** Loops rather than sweeping once: finishing a gated pane can start another UnlockActivity. */`

### `private class ActivityTracker`

```
    /**
     * Process-wide record of what this class started, and of every [UnlockActivity] `onCreate`.
     *
     * The creation count is the whole of the collapse assertion: `singleInstance` delivery to a
     * live instance is [Activity.onNewIntent], so a second `onCreate` is exactly and only what "the
     * system stacked a second prompt" looks like.
     */
```

Replaced with: `/** A second UnlockActivity onCreate is exactly "the system stacked a second prompt". */`

### `private class AppLockSnapshot`

```
/**
 * A verbatim copy of both app-lock preference files, taken before this class overwrites them and
 * written back afterwards.
 *
 * [AppLockStore.reset] is not a restore. It clears the credential salt — which makes an already
 * wrapped `deviceSecret` undecryptable, so a device that ran this suite would silently need
 * re-pairing — and it leaves whatever ran next with no PIN and no lock, neither of which is
 * necessarily what was there before. The store exposes no way to read the PIN hash back, so the
 * only honest restore is at the file level.
 *
 * The tripwire file is written **after** the encrypted one on the way back, for the same reason
 * [AppLockStore.reset] clears it first: `tripwireBroken()` is "a lock was configured but the PIN
 * hash is gone", so the moment where the marker is set and the hash is not must not exist. Getting
 * that order wrong here would arm [SecurityWipe.enforceTripwire] to destroy the device's data on
 * its next launch, from a teardown.
 */
```

Replaced with: `/** Write the tripwire file AFTER the encrypted one, or the teardown arms SecurityWipe. */`
