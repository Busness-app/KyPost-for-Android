# Comment archive - build files and resources

Comments removed from the build and resource files by the ponytail comment sweep.
Each block is the verbatim text as it stood in the source, under the element or line it sat above.

## app/build.gradle.kts

### `val keystorePropertiesFile = rootProject.file("keystore.properties")`

```
/**
 * Signing material, environment first.
 *
 * The environment wins so that `keystore.properties` can hold only non-secret fields — a path and
 * an alias — without changing how the build is invoked. `.gitignore` does not make a password in
 * the working tree safe: it stops one specific accident and does nothing about a tarball, an
 * rsync, a backup daemon, a Docker `COPY .`, or anything else running as the developer's user.
 *
 * `checkSigningSecretsAreNotInTheTree` below is what enforces it. See keystore.properties.example.
 */
```

### `fun signingValue(env: String, property: String): String? =`

```
/**
 * `providers.environmentVariable`, **never** `System.getenv`. The latter reads the *daemon's*
 * environment, which is fixed when the daemon starts and is not a declared configuration-cache
 * input, so a warm daemon silently produces an unsigned release from a shell that exported the
 * variables.
 */
```

### `val SECRET_PROPERTY_KEYS = listOf("storePassword", "keyPassword")`

```
/**
 * The two `keystore.properties` fields that must never hold a value.
 *
 * `storeFile` and `keyAlias` are paths and names, not secrets, and keeping them in the file is the
 * point of reading the environment first. These two are passwords.
 */
```

### `val keystoreFileHoldsSecrets = SECRET_PROPERTY_KEYS.any {`

```
/**
 * Whether the file currently holds a password.
 *
 * The environment-first read above was added so this file could be reduced to non-secret fields —
 * and then nothing checked whether it had been, so it sat there with the production store and key
 * passwords in it while the comment above explained at length why that was unacceptable. A
 * mitigation nobody is told they have not adopted is a mitigation nobody adopts.
 */
```

### `tasks.register("checkSigningSecretsAreNotInTheTree") {`

```
/**
 * Fails the build when the file holds a password, on demand rather than always.
 *
 * A task, not a hard failure at configuration time: a developer mid-migration must still be able to
 * build, and turning "you have not migrated yet" into "you cannot build" would get the check
 * deleted rather than the password moved. CI runs this task, so the repo cannot regress; locally it
 * is the warning above.
 */
```

### `lint {`

```
    /**
     * Lint findings that matter here fail the build.
     *
     * An explicit `fatal` list rather than `warningsAsErrors = true`. That lever needs a 383-entry
     * baseline file to be usable here, none of it security-relevant, and a suppression file that
     * large is indistinguishable from not running the check. Escalating the specific checks this
     * app's threat model depends on gives the same gate with real signal and no baseline.
     *
     * Add to this list when a new check guards something in `SECURITY.md`; do not add a baseline.
     */
```

### `isReturnDefaultValues = false`

```
            // OFF, so an unmocked android.* call throws instead of quietly returning a default.
            //
            // It was on, for one reason: `android.util.Log` otherwise throws "not mocked", which
            // would force Context-free production code (AppLockManager, DeviceEnvelope,
            // EnrollmentCeremony) to choose between recording a security-relevant event and being
            // unit-testable. The price was paid by every OTHER android.* call in JVM-tested code,
            // silently — `android.util.Base64` returned null, `org.json` returned nothing — so a
            // suite could go green over a body that did nothing. That is not hypothetical:
            // DeviceEnvelope's KDoc records its tests passing vacuously, with `= null` as the whole
            // function body leaving the suite green.
            //
            // src/test/java/android/util/Log.java buys the logging back on its own. It shadows the
            // stub with a real implementation, so the one API this flag existed for keeps working
            // while everything else now fails loudly. Flipping it cost ten test failures, all of
            // them that same Log class and none of them anything else — which is the measurement
            // that says the rule below was already being followed.
            //
            // THE RULE, now enforced by the runtime rather than by convention: production code
            // reachable from src/test must not call android.* for anything but logging. Use
            // java.util.Base64 and kotlinx.serialization, as DeviceEnvelope and Sec1Point do. Code
            // that genuinely needs the framework belongs in src/androidTest. `SourceRulesTest`
            // keeps the two historically silent APIs named explicitly.
```

### `// 'packageRelease' (APK) and 'signReleaseBundle' (AAB), matched exactly. A prefix match on`

```
/**
 * Fails the build when a **release variant** is configured without signing material.
 *
 * Gate on the *tasks that emit a signable artifact*, never on `gradle.startParameter.taskNames`.
 * Task names describe how the build was invoked rather than what it builds, and they are wrong in
 * both directions: `./gradlew :app:assemble` reaches `packageRelease` without the token "Release"
 * ever appearing, while `--configuration releaseRuntimeClasspath` contains "release" and is a
 * read-only query that must not abort.
 *
 * Without a signingConfig AGP does not fall back to the debug keystore — it emits an artifact that
 * `apksigner verify` rejects outright, so nothing downstream catches this for us.
 */
```

### `exclude(group = "com.google.crypto.tink", module = "tink")`

```
        // androidx.security.crypto and this connector both pull in Google's tink — the former via
        // tink-android, the latter via plain tink. Both jars ship the same com.google.crypto.tink.*
        // classes, so both on the classpath is a duplicate-class build failure. Keeping
        // tink-android is what the connector's own docs recommend.
        //
        // **Scoped to this dependency, never `configurations.all`.** A global exclusion of a crypto
        // artifact means a future version where the two jars stop being interchangeable surfaces as
        // NoClassDefFoundError in the push path at runtime, on a subset of devices, after a routine
        // bump — instead of a resolution failure at build time. The global form was also, silently,
        // excluding tink from AGP's own instrumented-test runner, whose seven artifacts are now
        // recorded in gradle/verification-metadata.xml rather than hidden.
```

### `implementation(libs.jsoup)`

```
    // Sanitizes sender HTML before it is quoted into the compose editor, which is a JavaScript
    // enabled WebView with a bound @JavascriptInterface. Parser-backed rather than hand-rolled on
    // purpose: an allowlist applied to a real DOM is the only form that survives mXSS and
    // malformed-markup tricks, and it is what the comparable clients (K-9, FairEmail) use.
```

### `implementation(libs.sqlcipher.android)`

```
    // Encryption at rest for kypost_mail.db, which holds every cached message body, the contact
    // book and PGP key material. It was a plain SQLite file: readable by anyone with the device
    // and root, or with an unlocked bootloader, whatever the app lock said. See
    // security/DatabaseKey.kt.
```

## app/proguard-rules.pro

### `# --- kotlinx.serialization -----------------------------------------------------------------`

```
# R8 rules for the release build.
#
# Most of what this app depends on ships its own consumer rules (Room, OkHttp, AndroidX,
# Firebase), so this file only covers what R8 cannot infer from bytecode alone: reflection-driven
# serialization, and the classes the platform instantiates by name from the manifest.
```

### `# Serializers are generated as nested classes and looked up reflectively; without these the`

```
# --- kotlinx.serialization -----------------------------------------------------------------
```

### `-if @kotlinx.serialization.Serializable class org.kysecurity.mail.**`

```
# The `-if @Serializable` rule below is the whole of what serialization needs, and it is precise:
# it keeps the companion and serializer of the annotated classes only.
#
# There used to be a blanket `-keepclasseswithmembers class org.kysecurity.mail.** { public static
# ** Companion; }` above it. That matches every class in this app with a companion object — which,
# in idiomatic Kotlin, is most of them — so it kept their names and undid a large part of the
# obfuscation this file exists to get.
#
# That regression is now caught by CI rather than by a reader remembering to look: the
# `R8 actually obfuscated the app` step in .github/workflows/ci.yml fails the release-build job if
# more than 30% of app classes keep their original name in
# `app/build/outputs/mapping/release/mapping.txt`. It was 22% when that step landed.
```

### `# Instantiated by class name by the framework, so R8 sees no reference to them. Only the class name`

```
# --- Manifest-declared components ----------------------------------------------------------
```

### `-keep class org.kysecurity.mail.KyPostApp { <init>(); }`

```
# Instantiated by class name by the framework, so R8 sees no reference to them. Only the class name
# and the no-arg constructor need to survive: `{ *; }` additionally kept every private field and
# method of five security-relevant classes, which is exactly what enabling R8 was meant to stop.
# Overridden framework methods are kept by the Android default rules, not by these.
```

### `# Keep line numbers so a release crash report is readable, but rename the source file so the`

```
# --- Diagnostics ---------------------------------------------------------------------------
```

## app/src/main/AndroidManifest.xml

### `<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />`

```
    <!--
      Required by Window.setHideOverlayWindows(), which every gated window and every consent dialog
      calls (see security/SecureWindow.kt). It is an install-time permission with no user prompt and
      no capability of its own: it only lets this app ask the system to hide OTHER apps' overlays
      while its own window is showing. Without it setHideOverlayWindows throws SecurityException —
      caught by ContactEditDraftTest, not by anything that reads like a permissions test.
    -->
```

### `<application`

```
    <!--
      No <queries> block. The Custom Tabs service query that used to be here existed solely for
      CustomTabsClient.getPackageName, and the Custom Tab handoff is gone — see WebmailTab.kt for
      why. Nothing this app does now needs to see which packages are installed: both remaining
      webmail launch modes ask the system to resolve an intent rather than asking what is there.
    -->
```

### `<meta-data`

```
        <!-- Which channel a system-tray notification lands on, for any FCM message that still
             arrives carrying a `notification` payload. Without this, Play Services invents its own
             fallback channel: not kypost_push, not kypost_mfa, so neither the IMPORTANCE_HIGH the
             MFA channel is created with nor any per-channel choice the user has made applies to it,
             and it can sit silenced while the relay reports every send as delivered.

             Belt to the braces of the relay now sending data-only for Android (see
             sendFcmMessage in kypost-server/worker/src/fcm.ts). Data-only messages route through
             onMessageReceived, where the app picks the channel itself and this is never consulted;
             the value only matters if that ever regresses. Literal rather than a reference to
             PushNotificationDispatcher.CHANNEL_ID because the manifest cannot read Kotlin — keep
             the two in step. -->
```

### `<!-- excludeFromRecents matches UnlockActivity: an authenticated approval prompt must not`

```
        <!-- taskAffinity="" keeps this in its own task, separate from MainActivity's. Without
             it, tapping the notification after the app process has died resolves to the app's
             existing (dead) task by affinity, which recreates MainActivity as the task root
             instead of reliably launching this activity on top — landing the user on the inbox
             instead of the approve/deny screen. -->
```

## app/src/main/keepRules/rules.keep

### `# If your project uses WebView with JS, uncomment the following`

```
# Add project specific R8 rules here.
# AGP will combine all keep rule files in src/main/keepRules to pass to R8
#
# For more details, see
#   https://d.android.com/r/tools/r8/keep-rules
```

### `(end of file)`

```

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}
```

## app/src/main/res/layout/activity_contact_detail.xml

### `<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/activity_contact_detail.xml -->
```

### `<LinearLayout`

```
        <!-- Populated programmatically in ContactDetailActivity.render() — one section header
             (row_contact_detail_header) plus one row (row_contact_detail_row) per populated field,
             skipping any field/section the contact has nothing in. -->
```

## app/src/main/res/layout/activity_contact_edit.xml

### `<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/activity_contact_edit.xml -->
```

## app/src/main/res/layout/activity_email_detail.xml

### `<TextView`

```
        <!--
            Anti-phishing warning, above the PGP bar because it is the more
            urgent thing to read: PGP describes how a message was protected,
            this says the message is trying to take over the device. A bare
            TextView rather than a LinearLayout — unlike the PGP and
            images-blocked bars there is no action button, because the
            dangerous links are already refused by SAFE_LINK_SCHEMES.
        -->
```

## app/src/main/res/layout/activity_inbox.xml

### `<androidx.swiperefreshlayout.widget.SwipeRefreshLayout`

```
            <!-- The weight moves to the refresh layout: it is now the child filling the column, and
                 the RecyclerView fills it. Leaving layout_weight on the RecyclerView would give it a
                 zero-height parent and an empty inbox. -->
```

## app/src/main/res/layout/activity_mfa_approval.xml

### `<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- fitsSystemWindows because this screen applies no insets of its own: under edge-to-edge the
     approve/deny buttons would otherwise sit under the navigation bar, and a partly obscured Deny
     is not an acceptable state for an authentication prompt. -->
```

### `<LinearLayout`

```
        <!-- Number matching is the ONLY way to approve. The server always mints the value it
             displays in the browser plus two decoys; a challenge that does not carry all three
             can be denied but never approved, so there is no bare Approve button to fall back
             to. See MfaNumberMatch. -->
```

## app/src/main/res/layout/activity_pgp_key.xml

### `<TextView`

```
        <!-- The scanning side is told to "confirm this fingerprint matches the other person's
             device". The presenting side had no screen showing its own fingerprint, so on an
             Android-to-Android exchange there was nothing to match against and the ceremony was
             a rubber stamp. -->
```

### `<TextView`

```
        <!-- The addresses are the binding: whoever holds this key can read mail sent to them.
             Confirming a name and a fingerprint without them verifies the key but not who it
             speaks for, so the card's addresses have to be on screen before the user accepts. -->
```

## app/src/main/res/layout/row_contact_address.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_address.xml -->
```

## app/src/main/res/layout/row_contact_detail_header.xml

### `<TextView xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_detail_header.xml -->
```

## app/src/main/res/layout/row_contact_detail_row.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_detail_row.xml -->
```

## app/src/main/res/layout/row_contact_event.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_event.xml -->
```

## app/src/main/res/layout/row_contact_im.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_im.xml -->
```

## app/src/main/res/layout/row_contact_two_field.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/row_contact_two_field.xml -->
```

## app/src/main/res/layout/view_expandable_section_header.xml

### `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"`

```
<!-- app/src/main/res/layout/view_expandable_section_header.xml -->
```

## app/src/main/res/values/strings.xml

### `<string name="compose_pgp_no_key_title">No key for some recipients</string>`

```
    <!-- Client-custody send from an enrolled device: this app holds the key and does the crypto.
         There is deliberately no pickup-link fallback on this path — the server-side one works by
         storing the message plaintext for 7 days, which is exactly what client-side protection
         exists to prevent. So a missing key is a dead end, and the copy says so plainly. -->
```

### `<string name="security_pin_too_short">PIN must be at least %1$d digits</string>`

```
    <!-- PIN policy feedback. A rejected PIN used to silently revert the toggle with no message. -->
```

### `<string name="contacts_device_sync_blocked_hostile_location">Device contact sync is unavailable while Hostile Location Protection is on — synced contacts are stored by the system, outside this app\'s protected storage</string>`

```
    <!-- Hostile Location Protection interactions with device contact sync -->
```

### `<string name="enrollment_title">Set up encrypted mail</string>`

```
    <!-- Device enrollment.

         EVERY STRING HERE DESCRIBES CAPABILITY, NEVER BEHAVIOUR. A user who completes this
         ceremony gets a device that HOLDS a key it does not yet USE: reading mail with the
         enrolled key is deferred (see the 2026-07-29 on-device-decryption spec, gated on a
         measurement nobody has taken). Saying "you can now read encrypted mail on this device"
         would be false until that lands. -->
```

### `<string name="enrollment_timed_out">Nothing has arrived in the last five minutes. Codes change every couple of minutes, so choose “Check again” for a current one, then type that in your browser.</string>`

```
    <!-- Must NOT promise the code above stays valid: codes roll every two minutes, and this state
         has no live window refreshing the one on screen. A user told "the code above is still the
         right one" who acts on it after the bucket rolls produces a browser-side mismatch — this
         feature's one alarm — from an entirely honest enrollment. "Check again" reopens a window,
         which re-derives the code, so that is what the copy points at. -->
```

### `<string name="email_no_content">There\'s nothing to show for this message. If your account uses encrypted mail, the server may not have finished preparing it — refresh your inbox and open it again.</string>`

```
    <!-- Shown when a message would otherwise render as a completely blank screen. Deliberately does
         NOT claim the message is encrypted: pgpEncrypted is omitempty server-side and defaults to
         false, so an encrypted message the server has not warmed yet is indistinguishable from an
         ordinary one, and asserting the stronger property on that evidence is the mistake
         BODY_UNAVAILABLE exists to prevent. It says what is true — there is nothing to show — and
         names the most likely reason without claiming it. -->
```

### `<string name="enrollment_ready_to_finish">Almost done</string>`

```
    <!-- Shown after the user dismisses the confirmation prompt. Must NOT show the code or ask for it
         to be typed again: this state is only reachable because the browser already read the code and
         sent the key, so repeating that instruction sends the user to redo a finished step — and the
         code it would display goes stale on the next bucket with no window left refreshing it.
         Describes capability, not behaviour: the key is held, not yet used to read anything. -->
```

### `<string name="enrollment_failed_could_not_open">This device could not open the key that was sent to it. That happens if your account\'s encryption key changed while you were setting this up — or if the key didn\'t come from your account. Nothing was saved on this device. Start again to try once more.</string>`

```
    <!-- The ONE failure with its own copy: the only point where this device can detect the
         substitution the ceremony exists to prevent. It DESCRIBES rather than ACCUSES, because a
         key rotation mid-ceremony is indistinguishable by construction from a hostile one — both
         produce exactly this — and an alarm that cries wolf is one users learn to dismiss. -->
```

### `<string name="push_pairing_encryption_hint">If your account uses encrypted mail, you can set this device up for it in Settings → Security.</string>`

```
    <!-- The pairing screen's pointer at enrollment.

         Worded conditionally ("If your account uses encrypted mail") rather than as a promise,
         because this line is NOT gated on hasPgpIdentity and never will be. Gating it would add an
         authenticated request to the pairing flow to answer a question the browser has usually
         already settled at first login — and hasPgpIdentity returns Boolean?, so a network failure
         would leave the app guessing anyway. Conditional wording also means it never goes stale: a
         user who creates their identity a week after pairing still finds the entry where this said
         it would be. -->
```

## app/src/main/res/values/themes.xml

### `<style name="Theme.KyPost" parent="Theme.MaterialComponents">`

```
    <!--
      This app renders its own 13 custom color palettes at runtime (see AppTheme.kt) rather than
      switching Android theme resources, so the base theme intentionally does NOT follow
      DayNight / system light-dark mode: doing so made system-level chrome we don't repaint
      ourselves (popup menus, dialogs, ripples, elevation overlays) flip to a stock light Material
      look that clashed with whichever custom palette was active. Keeping this theme fixed-dark
      and neutral keeps that chrome coherent no matter which in-app palette or system mode is set.
    -->
```

### `<item name="colorPrimary">@color/teal_200</item>`

```
        <!-- Primary brand color. Also drives AlertDialog button text color (MaterialComponents'
             borderless button style reads colorPrimary directly) since dialogs are the one piece
             of chrome this app doesn't repaint itself — see the note above. Must stay legible
             against colorSurface; the stock Android Studio purple_500 read as low-contrast on the
             dark surface, so this uses the app's existing teal accent instead. -->
```

### `<item name="colorSecondary">@color/teal_200</item>`

```
        <!-- Secondary brand color. -->
```

### `<item name="colorSurface">@color/app_chrome_surface</item>`

```
        <!-- Surfaces behind popup menus, dialogs, and elevation overlays. -->
```

### `<style name="Widget.KyPost.IconOnlyChip" parent="Widget.MaterialComponents.Chip.Action">`

```
    <!-- Chip's default padding budgets space for a text label after the icon (iconEndPadding +
         textStartPadding + textEndPadding), which pushes the icon left of center on an icon-only
         chip once that label is empty (Compose's formatting toolbar buttons). Zero out the
         text-side gutters and give the icon symmetric start/end padding instead. -->
```

## app/src/main/res/xml/data_extraction_rules.xml

### `<data-extraction-rules>`

```
<!--
  Restores the exclusions removed by be65d75, which assumed `allowBackup="false"` covered
  device-to-device transfer as well as cloud backup. It does not, for anything targeting
  API 31+: AOSP's BackupEligibilityRules ignores allowBackup for BackupDestination.DEVICE_TRANSFER
  via the IGNORE_ALLOW_BACKUP_IN_D2D compat change (@EnabledSince(S)), and per the Auto Backup
  docs a MISSING <device-transfer> section means that mode is "fully enabled for all content".
  So omitting this file opted the app INTO transferring everything — including the unencrypted
  kypost_mail.db (full plaintext message bodies, contacts, PGP keys) and the plaintext
  push_state DataStore (last 30 sender/subject pairs). `adb backup` cannot detect that gap,
  which is why the original verification step passed.

  Both sections must be present and explicit; an absent section is permissive, not restrictive.

  Excluding everything from device-transfer also fixes the converse bug: a legitimate transfer
  to the user's own new phone used to carry the plaintext app_lock_tripwire marker alongside an
  undecryptable app_lock_secure (its Keystore key cannot leave the source device), which made
  tripwireBroken() fire and silently wipe the app — including the OS contact rows the transfer
  had just copied — on first launch. With nothing transferred, the new install is simply unpaired.
-->
```

## app/src/main/res/xml/network_security_config.xml

### `<network-security-config>`

```
<!--
  Cleartext is refused explicitly rather than relying on targetSdk 28+'s default.

  The default is a property of the merged manifest: any dependency whose own manifest declares
  android:usesCleartextTraffic="true" flips it for the whole app, silently. Pairing deep links are
  already https-only (NativePairingDeepLinkParser), and every request from this app carries the
  device secret as a header, so there is no request it would be acceptable to send in the clear.

  cleartextTrafficPermitted="false" also disables non-TLS WebView loads, which matters for the
  email renderer once the user opts into remote content for a message.
-->
```

## app/src/main/res/xml/split_config.xml

### `<SplitPairRule`

```
    <!-- splitMinWidthDp is 800, NOT the 600 of the layout qualifier, and the two are deliberately
         different numbers answering different questions.

         600dp is where one screen earns a wider layout. 800dp is where a window can hold two of
         them. An embedded Activity is measured against its own pane, not the display, so splitting
         too early hands the primary 40% of a small window and produces a list narrower than a phone.

         Every threshold below was MEASURED on a Galaxy Z Fold 8 (SM-F971U1, Android 17), not taken
         from a spec sheet — density 420, so 2.625 px/dp:

           cover  1248x1972 px -> 475dp portrait, 751dp landscape
           inner  2448x1848 px -> 704dp book,     932dp rotated

         800 is the only threshold that gets all four right. It leaves the cover screen single-pane
         in both orientations and the inner display single-pane in book orientation, while still
         splitting the rotated inner display (932dp) into a comfortable 373/559 pair. An earlier
         value of 720 looked correct against the inner display alone and was wrong: the cover screen
         in landscape is 751dp, so it split into a 300dp list — narrower than the same screen in
         portrait, which is the exact failure this threshold exists to prevent.

         The rail does not survive into either pane at any ratio: the primary would need a ~1500dp
         window to reach the 600dp qualifier. That is Material's own rule — navigation type follows
         the pane's width, and a 373dp pane wants a bottom bar — not a workaround.

         finishPrimaryWithSecondary="never": closing a message must not close the inbox.
         finishSecondaryWithPrimary="always": the detail pane cannot outlive its list. -->
```

## build.gradle.kts

### `plugins {`

```
// Top-level build file where you can add configuration options common to all sub-projects/modules.
```

## gradle.properties

### `# Specifies the JVM arguments used for the daemon process.`

```
# Project-wide Gradle settings.
# IDE (e.g. Android Studio) users:
# Gradle settings configured through the IDE *will override*
# any settings specified in this file.
# For more details on how to configure your build environment visit
# http://www.gradle.org/docs/current/userguide/build_environment.html
```

### `org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8`

```
# Specifies the JVM arguments used for the daemon process.
# The setting is particularly useful for tweaking memory settings.
```

### `# When enabled, the Configuration Cache allows Gradle to skip the configuration`

```
# When configured, Gradle will run in incubating parallel mode.
# This option should only be used with decoupled projects. For more details, visit
# https://developer.android.com/r/tools/gradle-multi-project-decoupled-projects
# org.gradle.parallel=true
```

### `org.gradle.configuration-cache=true`

```
# When enabled, the Configuration Cache allows Gradle to skip the configuration
# phase entirely if nothing that affects the build configuration (such as build scripts)
# has changed. Additionally, Gradle applies performance optimizations to task execution.
```

### `kotlin.code.style=official`

```
# Kotlin code style for this project: "official" or "obsolete":
```

### `android.disallowKotlinSourceSets=false`

```
# KSP (Room's annotation processor) still registers generated sources via the legacy
# kotlin.sourceSets DSL, which AGP's built-in Kotlin compilation (used here since no explicit
# org.jetbrains.kotlin.android plugin is applied) rejects by default. This is the AGP-documented
# suppression for that specific KSP/built-in-Kotlin interaction (google/ksp#2729), not a general
# opt-out of the built-in Kotlin migration.
```

## gradle/libs.versions.toml

### `biometric = "1.1.0"`

```
# 1.1.0 is the newest STABLE release; everything above it (1.2.0-alpha05, 1.4.0-alpha07) is an
# alpha. Deliberately not bumped: this library backs the MFA approval gate and the unlock vault, and
# an alpha in that path trades a known-old dependency for an unknown-new one.
#
# REVIEW BY 2027-02-01. A standing "revisit when it goes stable" is a decision with no expiry, and
# this one is four years old on a minSdk 31 app — 1.1.0 predates every API level this app runs on.
# On that date, either bump or move the date deliberately; do not let it lapse silently. Check
# whether 1.2.0/1.4.0 have gone stable first, then validate on a device against
# BiometricUnlockVaultTest and Run4MfaCredentialGateTest.
```

## settings.gradle.kts

### `maven {`

```
        // Infomaniak's android-rich-html-editor (the compose screen's rich text body) is only
        // published to JitPack, not Maven Central.
        //
        // Scoped to that one group. JitPack builds artifacts on demand from git tags, and an
        // unfiltered entry makes it a candidate for *every* coordinate in the graph that is ever
        // missing upstream — while this dependency in particular owns a JavaScript-enabled WebView
        // with a bound @JavascriptInterface whose exportHtml feeds draft save and send. Resolution
        // order already means google() and mavenCentral() win for everything they hold, so this is
        // narrowing the blast radius rather than changing what resolves today.
```
