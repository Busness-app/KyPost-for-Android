# KyPost Android audit run 7

Scope: client injection/IPC, latest EmailDetail and Compose WebViews, HTML/URI handling,
intents/deep links/PendingIntent/notifications, attachment provider/exported surfaces, and the
new on-device PGP reading path.

Prior runs 1-6 were read from `~/security-audit-skill/kypost-android/run-{1..6}/findings.json`.
They already cover credential redirect/exfiltration, pairing trust, exported pairing history,
WebView quote XSS, email navigation/form issues, notification/MFA issues, attachment disclosure,
wipe/unpair/enrollment lifecycle issues, and multiple PGP enrollment/signature findings. Those
findings were excluded from this run.

Current boundary map:

- `MainActivity` and `PushPairingLinkActivity` are exported; all other activities in the manifest
  are non-exported. Pairing links require `kypost://native-pair` and are confirmation-gated.
- Push services, MFA approval, and the ephemeral attachment provider are non-exported. Notification
  PendingIntents are immutable and target non-exported activities.
- EmailDetail disables JavaScript, file/content access, DOM storage, and network loads by default;
  navigation is gesture-gated and scheme-allowlisted. Compose intentionally enables JavaScript,
  but quoted sender HTML passes through `QuotedHtmlSanitizer` before entering the editor bridge.
- PGP payload HTTP responses are capped at 32 MiB, but the new decryptor's post-decryption output
  has no equivalent bound.

Only one new confirmed finding survived validation: decompression amplification in `PgpDecryptor`.
