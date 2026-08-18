package org.kysecurity.mail.contacts.device

import android.content.Context
import android.content.SharedPreferences

/**
 * Whether device-contact sync is on, plus its two bookkeeping timestamps.
 *
 * **Every write is `commit()`, never `apply()`**, for the same reason
 * [org.kysecurity.mail.security.AppLockStore] gives: `apply()` returns before the write reaches
 * disk, and this file is both written by, and deleted by, [org.kysecurity.mail.security.SecurityWipe].
 *
 * That combination resurrects data. `PushRepository.purgeAccountScopedData` calls [setEnabled]
 * during the wipe; with `apply()` the write was still queued when the wipe's `sharedPrefs` step
 * deleted this file, and the in-memory map it eventually flushed still held **every key the file
 * had before the wipe** — so the deleted file came back with its old contents, behind a wipe that
 * reported Complete. `SecurityWipeTest.wipeAndResetApp_removesEveryOwnedPreferencesFile` is the
 * assertion; it caught this on API 31.
 *
 * Durability is the second reason, independent of ordering: sync gates on this toggle and not on
 * having a pairing, so an unpair whose `setEnabled(false)` never reached disk leaves the device
 * still syncing contacts. The writes are one boolean or one long each.
 */
class DeviceContactSyncSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }

    fun lastForeignScanAtEpochMs(): Long = prefs.getLong(KEY_LAST_FOREIGN_SCAN, 0L)

    fun setLastForeignScanAtEpochMs(epochMs: Long) {
        prefs.edit().putLong(KEY_LAST_FOREIGN_SCAN, epochMs).commit()
    }

    fun hasShownSyncIntro(): Boolean = prefs.getBoolean(KEY_SHOWN_INTRO, false)

    fun setHasShownSyncIntro(shown: Boolean) {
        prefs.edit().putBoolean(KEY_SHOWN_INTRO, shown).commit()
    }

    companion object {
        private const val PREFS_NAME = "org.kysecurity.mail.device_contacts"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_LAST_FOREIGN_SCAN = "last_foreign_scan_epoch_ms"
        private const val KEY_SHOWN_INTRO = "has_shown_sync_intro"
    }
}
