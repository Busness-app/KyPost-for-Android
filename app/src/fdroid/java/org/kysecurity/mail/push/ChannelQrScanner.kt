package org.kysecurity.mail.push

import androidx.activity.ComponentActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/** A FOSS scanner for the fdroid channel, which ships no Google code.
 *
 *  zxing-android-embedded supplies the capture activity and asks for CAMERA itself, so the only
 *  thing this app declares is the permission — see src/fdroid/AndroidManifest.xml. */
object ChannelQrScanner : QrScannerFactory {

    override fun create(activity: ComponentActivity): QrScanner {
        // Registered here, in onCreate, because the framework refuses registerForActivityResult
        // once the activity is STARTED. See QrScannerFactory.
        var pending: ((String) -> Unit)? = null
        val launcher = activity.registerForActivityResult(ScanContract()) { result ->
            // contents is null when the user backed out; "" is the documented dismissal value.
            val resume = pending
            pending = null
            resume?.invoke(result.contents.orEmpty())
        }

        return QrScanner {
            suspendCancellableCoroutine { continuation ->
                pending = { text -> if (continuation.isActive) continuation.resume(text) }
                // Dropped rather than left dangling: without this the callback would resume a
                // continuation the caller has already abandoned.
                continuation.invokeOnCancellation { pending = null }
                launcher.launch(
                    ScanOptions()
                        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        .setBeepEnabled(false)
                        // The pairing QR and the PGP key QR are both shown on a laptop screen in
                        // front of the user; a torch prompt is noise on both.
                        .setOrientationLocked(false),
                )
            }
        }
    }
}
