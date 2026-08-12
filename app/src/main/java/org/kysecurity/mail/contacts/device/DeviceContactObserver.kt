package org.kysecurity.mail.contacts.device

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.ContactsContract

class DeviceContactObserver(
    context: Context,
    private val coordinator: DeviceContactSyncCoordinator,
) : ContentObserver(Handler(Looper.getMainLooper())) {
    private val contentResolver = context.contentResolver
    private var isRegistered = false

    fun register() {
        if (isRegistered) return
        try {
            contentResolver.registerContentObserver(ContactsContract.Contacts.CONTENT_URI, true, this)
            isRegistered = true
            android.util.Log.d("DeviceContactSync", "Observer registered")
        } catch (e: Exception) {
            android.util.Log.e("DeviceContactSync", "Failed to register observer", e)
        }
    }

    fun unregister() {
        if (!isRegistered) return
        try {
            contentResolver.unregisterContentObserver(this)
            isRegistered = false
            android.util.Log.d("DeviceContactSync", "Observer unregistered")
        } catch (e: Exception) {
            android.util.Log.e("DeviceContactSync", "Failed to unregister observer", e)
        }
    }

    override fun onChange(selfChange: Boolean) {
        android.util.Log.d("DeviceContactSync", "onChange fired")
        coordinator.syncWithDebounce()
    }
}
