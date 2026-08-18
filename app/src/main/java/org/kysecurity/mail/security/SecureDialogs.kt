package org.kysecurity.mail.security

import android.app.Dialog

/**
 * Shows [this] with `FLAG_SECURE` set and overlays suppressed, so it is excluded from screenshots
 * and screen recordings exactly as the Activity behind it is, and cannot have its buttons covered
 * by another app.
 *
 * **`FLAG_SECURE` is a per-window flag and a Dialog creates its own window.** Setting it on the
 * Activity in [LockedActivity], [UnlockActivity] and
 * [org.kysecurity.mail.push.MfaApprovalActivity] therefore protects the Activity's window and nothing
 * else — every PIN this app asks for through an `AlertDialog` (set PIN, confirm PIN, change PIN,
 * disable lock, the credential-gate prompt, and the MFA fallback) was capturable by a screen
 * recorder or an overlay-capable app, while the identical field inlined in [UnlockActivity] was not.
 *
 * The same is true of [applyOverlayProtection], and it is the half that matters for a dialog that
 * asks the user to approve something: a consent prompt whose accept button can be covered is not a
 * consent prompt. The touch filter is re-applied to the dialog's whole view tree in
 * `setOnShowListener`, because the content view does not exist until then.
 *
 * Applies to both `android.app.AlertDialog` and `androidx.appcompat.app.AlertDialog`, which share
 * [Dialog] as a supertype. Use it for anything that renders a secret or asks for a decision; there
 * is no cost to using it for anything else.
 */
fun <T : Dialog> T.showSecurely(): T {
    window?.applySecureFlag()
    window?.applyOverlayProtection()
    setOnShowListener { window?.decorView?.filterObscuredTouchesRecursively() }
    show()
    return this
}
