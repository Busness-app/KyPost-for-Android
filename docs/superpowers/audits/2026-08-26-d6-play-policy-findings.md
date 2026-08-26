# D6 — Play policy audit, and what to actually do with it

Run 2026-08-26 with the `play-policy-insights` skill. Item **D6** of the launch
plan: *"Run the audit before submitting. The Data Safety declaration for a mail
client with a local LLM and a push relay is not obvious, and a rejection costs a
review cycle."*

The tool's own output is preserved verbatim alongside this file as
`2026-08-26-play-policy-insights-report.md`. This document is the part the
generated report cannot give you: which of its inputs were real, which were
substring noise, and the one thing most likely to cost a review cycle.

**Audited tree:** the D3 (2/2) branch — `feat/fdroid-foss-scanner`, the state in
which the fdroid flavor carries no Google code and CAMERA is scoped to fdroid
alone. Several conclusions below depend on that, and are noted where they do.

**Overall status: 🟡 Needs Review.** No policy violations. Two `IMPORTANT`
findings, both administrative rather than code defects, and both verified
against source rather than inferred.

---

## 1. The finding that can actually get you rejected

**A Play reviewer cannot use this app at all.**

There is no login screen anywhere — no password, no `signIn`, no registration
wall. The gate is *device pairing*: the app is inert until it scans a
`kypost://native-pair` QR minted by a running KyPost server. Two independent
surfaces say so in as many words:

- `strings.xml:11` — "Not paired yet. Pair this device before using Relay mode."
- `strings.xml:373` — "Not paired yet. Pair this device via the Pairing menu first."

This is a stronger gate than a password, and the usual remedy does not work:
**there is no username and password you can type into Play Console that will let
a reviewer in.** They need a reachable server.

**Before submitting:**

1. Stand up a reviewer-accessible KyPost instance.
2. In Play Console → *App access*, supply a working pairing QR (or the
   `kypost://native-pair` URI) **and** written steps for using it.
3. State that the app requires an external self-hosted server, so a reviewer who
   cannot pair reads it as by-design rather than as a broken build.

## 2. The Data Safety item the launch plan predicted

Everything this app sends goes to a server **the user operates** — except one
path, and that path is the whole subtlety.

Push notifications on the `play` and `github` flavors travel through a
**developer-operated Cloudflare Worker relay and Firebase**. That is third-party
sharing in Play's sense, and it must be declared:

- an FCM registration token and `Build.MODEL` as `deviceName` are sent on every
  pairing (`NativeRegistration.kt:86`);
- `PushPayload` carries `senderName`, `emailSubject` and `keywords`
  (`PushPayload.kt:6-12`), so previews *can* carry message content.

**Previews are opt-in per account and off by default** — the default
configuration sends a content-free "You have a new email." Say that explicitly
in the Data Safety free-text, because the honest answer differs between the
default and opted-in states and a reviewer cannot tell which you mean.

Note this is a **play/github** concern. The fdroid flavor uses UnifiedPush and
touches neither the relay nor Firebase.

## 3. What the app conspicuously does not do

Worth stating in the listing, because it is unusual and a reviewer will not
assume it. Verified by searching every source set:

- **No hardware or advertising identifier.** No `Settings.Secure.ANDROID_ID`,
  `getDeviceId`, `AdvertisingIdClient`, `getImei`, `getSubscriberId`,
  `Build.SERIAL` or `getMacAddress` — anywhere.
- **No analytics, crash-reporting or ad SDK.** No Crashlytics, no Firebase
  Analytics, no GMS Ads, no AppsFlyer/Mixpanel/Amplitude/Sentry.

The identifier the app *does* transmit is assigned by the user's own server at
pairing. Declare *Device or other IDs* — but say in the free-text that no
platform identifier is read, or the declaration reads worse than the reality.

## 4. Contacts access is justified, and this is why

`READ_CONTACTS`/`WRITE_CONTACTS` are broad permissions that Play expects apps to
avoid in favour of the Contact Picker. The exemption is for "broad, continuous
contacts synchronization … full contact managers", and this is squarely that:

- `DeviceContactObserver.kt:19` registers a `ContentObserver` on
  `ContactsContract.Contacts.CONTENT_URI` for continuous change detection;
- `KyPostContactAuthenticator` registers a real `AccountManager` sync account;
- there is a sync worker, a conflict resolver, a field merge and a purge.

It is also opt-in and runtime-gated, and `DeviceContactSyncEnabler.checkAndEnable()`
refuses outright while Hostile Location Protection is on. No finding.

## 5. Where the scanner was wrong

Recorded so nobody re-derives it, and as a caution against reading the raw
report literally. The scanner substring-matches, and most of its categories for
this app are noise:

| Flagged | Actually matched | Verdict |
| --- | --- | --- |
| `RACE_ETHNICITY` | `race` inside **t·race** | false positive |
| `AUDIO` | `record` (database record), `voicemail` (a contact field type) | false positive |
| `MUSIC` / `OTHER_AUDIO` | `audio/mpeg`, `audio/ogg` — attachment MIME types | false positive |
| `WEB_BROWSING_HISTORY` | `WebView` — used to render HTML mail | false positive |
| `OTHER_APP_PERFORMANCE` | `getDatabasePath` — the local encrypted DB | local-only, exempt |
| `APP_INTERACTIONS` | `onClickListener` | false positive |
| `DEVICE_ID` | the **class name** `AndroidIdentitySource` | false positive (see §3) |

### The one to watch: the scanner unions all three flavor manifests

It reported `android.permission.CAMERA` as requested by the app. **The Play
build does not request it.** Confirmed with `aapt2 dump permissions` on the
release APKs: play and github request no camera permission; only fdroid does,
for its FOSS scanner.

This matters directly: play and github scan with ML Kit, which runs the camera
inside the Google Play Services process, so those builds need no camera
permission at all — and that absence is a Data Safety claim on the listing. A CI
step added with D3 (2/2) fails the build if either flavor ever acquires it.

**Do not fill in the Data Safety form from a whole-repo scan of a multi-flavor
project.** Declare against the `play` artifact.

---

## Suggested Data Safety declaration

All *App functionality*, all *linked to the user*:

Address (contact postal fields, not the user's location) · Contacts ·
Device or other IDs · Emails · Files and docs (attachments) · Name ·
Other user-generated content

**Shared with third parties:** only the push path in §2 — and only for the play
and github flavors.

## Checklist

- [ ] Reviewer-accessible KyPost server, with pairing QR and instructions in
      Play Console → App access. **This is the rejection risk.**
- [ ] Data Safety completed against the **play** artifact, not a repo scan.
- [ ] Free-text states: previews off by default; mail server is user-operated;
      no hardware or advertising identifier is read.
- [ ] Decide what the account-deletion URL points to, given there is no
      developer-held account. In-app *Unpair device* already performs a real
      server-side removal (`DeregisterClient.kt:44`), not just a local clear.
- [ ] Confirm whether the relay retains a per-device token after deregistration,
      and say so on that page.

## Not covered

The launch plan mentions a **local LLM**. There is none in this Android app.
Searched every source set and the dependency catalog for `gguf`, `onnx`,
`tflite`, `litert`, `mediapipe`, `genai`, `gemini-nano`, `ExecuTorch` and
`llama`: no match. `app/src/main/assets/` contains only fonts.

(The `llm` substring does match — inside "Enro**llm**ent". Same trap as §5.)

So there is nothing to declare on this side. If inference happens on the Linux
client or the server and mail text reaches it, that belongs in a declaration
this audit did not examine.
