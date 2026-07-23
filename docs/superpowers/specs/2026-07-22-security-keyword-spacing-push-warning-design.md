# Security/Keyword screen spacing + push data-leak warning

## Problem

1. `SecuritySettingsActivity` and `KeywordSettingsActivity` build their layouts
   programmatically and pass raw pixel values (e.g. `setPadding(24, 24, 24, 24)`,
   `setPadding(0, 4, 0, 16)`) directly to view APIs that expect real pixels. On a
   typical xxhdpi phone (density ≈3) that's roughly 8dp of container padding and
   1–5dp between controls — the screens read as squished on any real device
   regardless of content.
2. The "Require unlock to receive push/MFA" toggle only gates whether push
   content is delivered *while the device is locked*. It does not address (and
   the existing copy doesn't mention) that push notifications inherently relay
   sender/subject metadata through a third-party push service (Firebase or
   UnifiedPush) before reaching the device, on every delivery, toggle on or off.
   Users have no way to tell from this screen that push relay itself is a data
   exposure they could eliminate by moving to Pull delivery mode.

## Design

### 1. Spacing

Add a small local `dp()` density-conversion helper to each activity (same
pattern already used in `AboutDialog.kt`: `(value * resources.displayMetrics.density).toInt()`).
Convert existing `setPadding` calls to use it, and add vertical margins
between sibling controls that currently sit flush against each other
(switch → its helper text → the next switch/button; checkbox → checkbox).
Target roughly 20dp container padding, 12–16dp between distinct controls,
6–8dp between a control and its directly-associated helper text. No new
container types — same `LinearLayout`/`ScrollView` structure, just density-aware
spacing.

Applies to both `SecuritySettingsActivity.kt` and `KeywordSettingsActivity.kt`.

### 2. Push data-leak warning

Add a new warning callout, always visible, directly under the existing
`security_credential_gate_intro` text in `SecuritySettingsActivity` (not
gated on the toggle's on/off state — the relay exposure exists either way).

- New string resource `security_credential_gate_leak_warning`:
  > "Push always sends the sender and subject through Google/UnifiedPush
  > relay servers, even with this on. For zero leakage, ask your server
  > admin to switch this device to Pull mode instead."
- Visually distinct from the plain explanatory `TextView`s already on the
  screen: reuse the existing `COLOR_WARNING` (`#ffd64d`) token — defined in
  `AppTheme.kt` but currently only used for a swipe-action color, not yet for
  a text callout — styled with the same stroke+12%-fill panel shape the app
  already uses for the danger-button pattern (`dangerButtonBackground()` /
  `applyDangerButtonTheme`), applied to a `TextView` instead of a `Button`.
  Add a small `applyWarningCalloutTheme(context, textView)` helper in
  `AppTheme.kt` alongside the existing `applyDangerButtonTheme` for this.
- No new interactive control: Pull delivery mode is server-authoritative
  (`DeliveryMode` is "mirrored from the server," per `PullNotification.kt`)
  with no existing client-side switch anywhere in the app, so this is
  informational text only, not a new toggle.

## Out of scope

- Any change to delivery-mode selection/negotiation logic.
- Any change to the existing "Require unlock..." on/off warning dialog
  (`confirmEnableCredentialGate`), which addresses a different, already-
  correct concern (notifications not arriving while locked).
- Spacing changes to any screen other than Security and Keyword settings.
