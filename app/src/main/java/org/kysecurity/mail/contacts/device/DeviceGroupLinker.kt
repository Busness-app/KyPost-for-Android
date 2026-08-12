package org.kysecurity.mail.contacts.device

import android.content.ContentValues
import android.content.Context
import android.provider.ContactsContract
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.GroupEntity
import org.kysecurity.mail.data.GroupLinkEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Bridges Room's local group cache ([org.kysecurity.mail.data.GroupEntity]) to Android's
 * `ContactsContract.Groups` rows scoped to this app's sync account, mirroring the remote-ID <->
 * local-row-ID bridging [org.kysecurity.mail.data.DeviceContactLinkEntity] already solves for contacts
 * themselves. Only ever materializes a *backend* group onto the device (find-or-create + rename
 * in place) — it never creates a backend group from a device-side one, matching
 * `Client_Contact_Update.md` Part 2 point 3's explicit one-direction (backend -> device) scoping
 * for group sync.
 */
class DeviceGroupLinker(
    private val context: Context,
    private val db: AppDatabase,
) {
    private val contentResolver = context.contentResolver

    /**
     * Returns the Android `Groups._ID` row for [groupId]/[groupName]: reuses an existing
     * [GroupLinkEntity] if present (renaming the on-device `TITLE` in place if [groupName]
     * changed since the link was created), otherwise finds an existing on-device `Groups` row
     * matching by `TITLE == groupName` to avoid duplicating a group the user already has, and
     * only creates a new row as a last resort.
     */
    suspend fun ensureAndroidGroupRowId(groupId: String, groupName: String): Long? = withContext(Dispatchers.IO) {
        val existingLink = db.groupLinkDao().getByGroupId(groupId)
        if (existingLink != null) {
            renameIfNeeded(existingLink.androidGroupRowId, groupName)
            return@withContext existingLink.androidGroupRowId
        }

        val rowId = findExistingGroupRowId(queryAccountGroups(), groupName) ?: createAndroidGroup(groupName)
        if (rowId != null) {
            db.groupLinkDao().upsert(GroupLinkEntity(groupId = groupId, androidGroupRowId = rowId))
        }
        rowId
    }

    private fun queryAccountGroups(): List<Pair<Long, String>> {
        val projection = arrayOf(ContactsContract.Groups._ID, ContactsContract.Groups.TITLE)
        val selection = "${ContactsContract.Groups.ACCOUNT_TYPE} = ? AND " +
            "${ContactsContract.Groups.ACCOUNT_NAME} = ? AND ${ContactsContract.Groups.DELETED} = 0"
        val selectionArgs = arrayOf(DeviceContactAccount.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_NAME)

        val results = mutableListOf<Pair<Long, String>>()
        contentResolver.query(
            ContactsContract.Groups.CONTENT_URI,
            projection,
            selection,
            selectionArgs,
            null,
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                val id = cursor.getLong(cursor.getColumnIndexOrThrow(ContactsContract.Groups._ID))
                val title = cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Groups.TITLE)) ?: ""
                results.add(id to title)
            }
        }
        return results
    }

    private fun createAndroidGroup(groupName: String): Long? {
        val uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
            .build()
        val values = ContentValues().apply {
            put(ContactsContract.Groups.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
            put(ContactsContract.Groups.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
            put(ContactsContract.Groups.TITLE, groupName)
            put(ContactsContract.Groups.GROUP_VISIBLE, 1)
        }
        val resultUri = runCatching { contentResolver.insert(uri, values) }.getOrNull() ?: return null
        return resultUri.lastPathSegment?.toLongOrNull()
    }

    /**
     * Renames the on-device `Groups.TITLE` for [androidGroupRowId] to [groupName] in place, if
     * it differs from the current on-device title. Public (not just called from
     * [ensureAndroidGroupRowId]) so [org.kysecurity.mail.contacts.GroupSyncRepository]'s regular
     * full-refresh sync cycle can also invoke it for every *already-linked* group -- the plan's
     * Part 2 point 4 requires a backend group rename to reach the device on the next sync, not
     * only when a brand-new not-yet-linked contact happens to reference that group.
     */
    suspend fun renameIfNeeded(androidGroupRowId: Long, groupName: String) = withContext(Dispatchers.IO) {
        val currentTitle = contentResolver.query(
            ContactsContract.Groups.CONTENT_URI,
            arrayOf(ContactsContract.Groups.TITLE),
            "${ContactsContract.Groups._ID} = ?",
            arrayOf(androidGroupRowId.toString()),
            null,
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(cursor.getColumnIndexOrThrow(ContactsContract.Groups.TITLE)) else null
        }

        if (currentTitle != null && currentTitle != groupName) {
            val uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
                .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true")
                .build()
            val values = ContentValues().apply { put(ContactsContract.Groups.TITLE, groupName) }
            runCatching {
                contentResolver.update(uri, values, "${ContactsContract.Groups._ID} = ?", arrayOf(androidGroupRowId.toString()))
            }
        }
    }
}

/**
 * Pure join: for every [links] entry whose backend group still exists in the freshly-synced
 * [groups] cache, resolves the (androidGroupRowId, freshName) pair that should be passed to
 * [DeviceGroupLinker.renameIfNeeded]. A link whose group was deleted from the backend (and thus
 * dropped from [groups] by [org.kysecurity.mail.contacts.GroupSyncRepository]'s full refresh) is
 * skipped -- there's no fresh name to rename to. Extracted as a standalone pure function so the
 * "which already-linked groups need a rename pass" decision is unit-testable without a real
 * `ContentResolver`; the actual current-title comparison and write happen inside
 * [DeviceGroupLinker.renameIfNeeded] itself.
 */
internal fun groupRenameTargets(links: List<GroupLinkEntity>, groups: List<GroupEntity>): List<Pair<Long, String>> {
    val groupsById = groups.associateBy { it.id }
    return links.mapNotNull { link -> groupsById[link.groupId]?.let { link.androidGroupRowId to it.name } }
}

/** Pure find-or-create decision: does any existing on-device group (scoped to our account)
 *  already have this exact title? Extracted so the matching rule is unit-testable without a real
 *  `ContentResolver`. */
internal fun findExistingGroupRowId(existingGroups: List<Pair<Long, String>>, groupName: String): Long? =
    existingGroups.firstOrNull { it.second == groupName }?.first
