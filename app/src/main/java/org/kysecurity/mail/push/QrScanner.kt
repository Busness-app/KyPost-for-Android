package org.kysecurity.mail.push

import androidx.activity.ComponentActivity

/** Scans one QR code. */
fun interface QrScanner {
    /** The raw text of a scanned code, or "" when the user dismissed the scanner without one.
     *
     *  Never throws for a dismissal: cancelling is a normal outcome on both screens that use
     *  this, and treating it as an error puts a failure toast in front of a user who simply
     *  changed their mind. */
    suspend fun scan(): String
}

/** The QR scanner this channel ships.
 *
 *  play and github use ML Kit's, which runs the camera inside the Google Play Services process
 *  and therefore needs no CAMERA permission from this app. fdroid cannot use it — F-Droid refuses
 *  proprietary dependencies — so it ships a FOSS scanner in-process, which does need the
 *  permission. That permission is declared in src/fdroid/AndroidManifest.xml and must stay there:
 *  moving it to src/main would hand it to the Play build, which does not need it and would then
 *  have to declare it under Data Safety.
 *
 *  [create] MUST be called UNCONDITIONALLY, as a property initializer, exactly like the
 *  permission launchers these two screens already hold. Two reasons, and the second is the one
 *  that bites:
 *
 *   - the framework refuses registerForActivityResult once the activity is STARTED, so a
 *     lazily created scanner throws the first time a user taps scan; and
 *   - ActivityResultRegistry keys unnamed registrations by their ORDER within the activity
 *     instance. LockedActivity.onCreateUnlocked does not run when the app is locked, so
 *     registering there would produce one order on an unlocked creation and another on a locked
 *     one, and a result delivered after recreation would go to the wrong callback. */
fun interface QrScannerFactory {
    fun create(activity: ComponentActivity): QrScanner
}
