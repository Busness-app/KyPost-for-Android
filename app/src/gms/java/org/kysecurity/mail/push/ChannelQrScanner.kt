package org.kysecurity.mail.push

import androidx.activity.ComponentActivity
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.tasks.await

/** ML Kit's code scanner, for the play and github channels.
 *
 *  Nothing to register: the scan is a Task, and the camera runs in the Play Services process, so
 *  this app needs no CAMERA permission. See QrScannerFactory for why that matters. */
object ChannelQrScanner : QrScannerFactory {
    override fun create(activity: ComponentActivity): QrScanner = QrScanner {
        GmsBarcodeScanning.getClient(activity).startScan().await().rawValue.orEmpty()
    }
}
