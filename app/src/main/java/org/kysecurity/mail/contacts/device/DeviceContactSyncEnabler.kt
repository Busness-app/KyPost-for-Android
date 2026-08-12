package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import kotlinx.coroutines.launch

/** Shared permission-check -> request -> enable sequence for device contact sync, used by both
 *  the Contacts screen's menu toggle and the pairing screen's first-scan intro popup so there's
 *  one canonical enable path instead of two copies of this logic. */
class DeviceContactSyncEnabler(
    private val activity: AppCompatActivity,
    private val permissionLauncher: ActivityResultLauncher<Array<String>>,
    private val onEnabled: () -> Unit = {},
) {
    /** Returns true if permissions had to be requested asynchronously — the caller must wait for
     *  the permission launcher's own callback (which should call [enableAfterPermissionGrant] on
     *  grant) before doing anything that assumes sync is now enabled. Returns false if it
     *  resolved synchronously because permissions were already granted. */
    fun checkAndEnable(): Boolean {
        // Refused, not just defaulted off: synced contacts land in the OS contacts provider, which
        // Hostile Location Protection's in-memory database does not cover.
        if (!DeviceContactsRuntime.graph(activity).syncPermitted()) {
            Toast.makeText(activity, R.string.contacts_device_sync_blocked_hostile_location, Toast.LENGTH_LONG).show()
            return false
        }

        val readContactsGranted = ContextCompat.checkSelfPermission(
            activity,
            Manifest.permission.READ_CONTACTS,
        ) == PackageManager.PERMISSION_GRANTED
        val writeContactsGranted = ContextCompat.checkSelfPermission(
            activity,
            Manifest.permission.WRITE_CONTACTS,
        ) == PackageManager.PERMISSION_GRANTED

        return if (readContactsGranted && writeContactsGranted) {
            enableAfterPermissionGrant()
            false
        } else {
            permissionLauncher.launch(
                arrayOf(
                    Manifest.permission.READ_CONTACTS,
                    Manifest.permission.WRITE_CONTACTS,
                ),
            )
            true
        }
    }

    fun enableAfterPermissionGrant() {
        val graph = DeviceContactsRuntime.graph(activity)
        if (!graph.syncPermitted()) {
            Toast.makeText(activity, R.string.contacts_device_sync_blocked_hostile_location, Toast.LENGTH_LONG).show()
            return
        }
        activity.lifecycleScope.launch {
            try {
                graph.accountManager.ensureAccount()
                graph.settings.setEnabled(true)
                graph.observer.register()
                DeviceContactSyncScheduler.ensurePeriodic(activity)
                graph.coordinator.syncNowAsync()
                Toast.makeText(activity, R.string.contacts_device_sync_enabled_toast, Toast.LENGTH_SHORT).show()
                onEnabled()
            } catch (e: Exception) {
                Toast.makeText(activity, "Failed to enable device sync: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
