# KyPost for Android

KyPost is an Android email client backed by a self-hosted KyPost relay. It shows keyword-based inbox tabs and synchronizes contacts in both directions. Native-push pairing authenticates relay access and contact sync. The app gets push notifications through native backend pairing and FCM. The client does not use Novu. The backend owns any Novu integration behind its own registration endpoint.

## Features

- **Mail**: The paired KyPost relay proxies mail; the app stores no mail credentials on the device.
- **Keyword tabs**: Inbox tabs come from server tab and label fields. Tune the tabs in the Keywords screen.
- **Compose**: The To, Cc, and Bcc fields complete recipients from local contacts. An address-book picker adds recipients directly.
- **Contacts**: A two-way contact sync runs against a self-hosted KyPost server. Open it from the Inbox overflow menu.
- **PGP key signing**: One screen shows your own PGP public-key QR code. The same screen scans the QR code of another person and saves that key onto an existing contact.
- **MFA push approval**: Push notifications approve or deny KyPost account logins. An in-app screen does the same when OEM background limits block the action notification.
- **Themes**: The app shares theme presets with the KyPost web app. The default theme is **Patina Ky**. Select a theme in the Themes screen.
- **Push notifications**: The app shows system notifications and keeps an in-app notification history for new mail. Each user selects a delivery mode (`push` or `pull`).

## Push notification pairing

- The app pairs the device from a desktop deep link or QR code:
  `kypost://native-pair?sub=<subscriberId>&hash=<subscriberHash>&srv=<serverUrl>&reg=<registrationUrl>&pt=<pairingToken>`
- The app stores the pairing proof material in a Keystore-backed `EncryptedSharedPreferences` file. This material is the subscriber id, the subscriber hash, the server URL, the registration URL, the pairing token, and the last known device id. The app does not store this material in the plaintext DataStore that holds the notification history and the sync status.
- The app registers the FCM token against the native registration endpoint of the backend. It uses `reg` from the QR code. If `reg` is absent, it derives `{srv}/api/notifications/native/register`. The app repeats this call on pair and on each token refresh.
- The app marks the device as paired only after the registration call succeeds (`ok:true` or `synced:true`). A QR code scan alone does not pair the device.
- The app handles these FCM data payload keys: `messageId`, `senderName`, `emailSubject`, and `Keywords`.
- The app shows system notifications and keeps an in-app notification history.
- Each user selects a **delivery mode** (`push` or `pull`) on the web Notifications page. In `pull` mode the server sends nothing to FCM. The app polls the server directly.

## Pull mode (FCM and relay bypass)

- The native registration response also returns `deliveryMode` (`push` or `pull`) and `pullEndpoint`. The app stores both values. If `pullEndpoint` is absent, the app derives `{srv}/api/notifications/native/pull`.
- In `pull` mode the app polls `GET {pullEndpoint}?sub=&hash=&after=<cursor>`. The query parameters are the only authentication. The `hash` value is the same URL-encoded subscriber HMAC. The request uses no session and no bearer token. FCM stays registered but is not the source of truth.
- The app renders each returned notification through the dispatcher that handles an FCM data message. The tap behavior is therefore identical.
- The strictly increasing `seq` value removes duplicates. The app advances a durable per-subscriber `lastCursor` to `max(lastCursor, response.cursor)`. It advances the cursor only after it hands off the notifications, so a crash causes a re-fetch instead of a lost notification.
- The `deliveryMode` value in the register response and in the pull response is authoritative. A change to `push` on the web stops the polling. A change to `pull` starts the polling again. The app reads the value again on every app foreground.
- **Cadence tradeoff**: pull mode has no push message to wake the app. Background delivery uses WorkManager periodic work at the platform minimum of 15 minutes. The app also pulls immediately on app foreground and after each pairing. Near real-time background delivery needs a foreground service with a short poll loop and a persistent notification. This is not the default by design. The app backs off after `400`, `401`, and `503` responses and after network errors, so it does not loop tightly.

## Firebase setup

1. Create or update the Firebase Android app for the application id `org.kysecurity.mail`.
2. Download `google-services.json`.
3. Put the file at `app/google-services.json`.
4. Enable FCM in the Firebase project settings.

## Notification permission behavior (Android 13 and later)

- The app requests `POST_NOTIFICATIONS` at launch.
- If the user denies the permission, the app still parses each delivered push payload and saves it to the in-app history. The app does not show system notifications.

## Pairing from a desktop QR code

1. The desktop web app shows a QR code with the deep link. The link contains `sub`, `hash`, `srv`, `pt`, and optionally `reg`.
2. In the Push Notifications screen, tap **Scan QR Code**. You can also open the deep link directly, because the app is a handler for `kypost://native-pair`.
3. The app validates the required parameters (`sub`, `hash`, `srv`, `pt`) and resolves the registration endpoint.
4. The app calls the native registration endpoint with the FCM token. The app marks the device as paired only on success.
5. On each later FCM token refresh, the app repeats the same registration call with the stored pairing.

## Troubleshooting checklist

- Make sure the deep link scheme and host are exactly `kypost://native-pair`. The app no longer supports the legacy `novu-pair` host or the old `llamalabels://` scheme.
- Make sure the required query parameters exist: `sub`, `hash`, `srv`, and `pt`.
- Make sure the device can reach the resolved registration endpoint (`reg`, or `{srv}/api/notifications/native/register`).
- Make sure the Firebase project configuration matches the package `org.kysecurity.mail`.
- If the registration fails with `400`, the request was malformed or missed a field.
- If the registration fails with `401`, the pairing token (`pt`) is invalid or expired. Scan a new QR code.
- If the registration fails with `503`, the backend has no `PAIRING_SECRET` configuration. The app cannot retry around this error.
- If Android 13 or later shows no notification, make sure the user granted the notification permission.

## Build and test

```sh
./gradlew testDebugUnitTest
```

```sh
./gradlew assembleDebug
```

Instrumented tests need a connected device or emulator. They cover the pairing store that uses `EncryptedSharedPreferences`.

```sh
./gradlew connectedDebugAndroidTest
```

## Test coverage

- Deep-link parser tests (`NativePairingDeepLinkParserTest`)
- Pairing validation tests (`PairingValidatorTest`)
- Native registration endpoint resolution tests (`NativeRegistrationEndpointResolverTest`)
- Payload parser tests (`messageId`, `senderName`, `emailSubject`, `Keywords`)
- Native registration request mapper tests (`NativeRegistrationRequestMapperTest`)
- Secure pairing store round-trip and encryption tests (`SecurePairingStoreTest`, instrumented)
```
