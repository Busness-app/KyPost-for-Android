package com.urlxl.mail.data

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies MIGRATION_3_4 (Task 2 extended contact fields) applies cleanly against a real
 * version-3 `contacts` table, matching the instrumentation-test convention documented in
 * app/src/androidTest/AGENTS.md (MigrationTestHelper needs Android's real SQLite, which JVM
 * unit tests under app/src/test can't provide).
 */
@RunWith(AndroidJUnit4::class)
class MigrationTest {

    @get:Rule
    val helper: MigrationTestHelper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        AppDatabase::class.java.canonicalName,
        FrameworkSQLiteOpenHelperFactory(),
    )

    @Test
    fun migrate3To4_addsExtendedContactColumns_andPreservesExistingRow() {
        helper.createDatabase(TEST_DB, 3).apply {
            execSQL(
                "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson) " +
                    "VALUES ('uid-1', 1, 'Ada Lovelace', '[]', '[]', '[]')",
            )
            close()
        }

        val migrated = helper.runMigrationsAndValidate(TEST_DB, 4, true, AppDatabase.MIGRATION_3_4)

        migrated.query("SELECT * FROM contacts WHERE uid = 'uid-1'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals("Ada Lovelace", cursor.getString(cursor.getColumnIndexOrThrow("fn")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("groupIDsJson")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("pgpKey")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("imsJson")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("websitesJson")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("relationsJson")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("eventsJson")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("phoneticGivenName")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("phoneticFamilyName")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("department")))
            assertEquals("[]", cursor.getString(cursor.getColumnIndexOrThrow("customFieldsJson")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("pronouns")))
            assertEquals(true, cursor.isNull(cursor.getColumnIndexOrThrow("photoRef")))
        }
    }

    @Test
    fun migrate4To5_createsGroupTables_andPreservesExistingContactRow() {
        helper.createDatabase(TEST_DB, 4).apply {
            execSQL(
                "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson) " +
                    "VALUES ('uid-1', 1, 'Ada Lovelace', '[]', '[]', '[]')",
            )
            close()
        }

        val migrated = helper.runMigrationsAndValidate(TEST_DB, 5, true, AppDatabase.MIGRATION_4_5)

        migrated.query("SELECT * FROM contacts WHERE uid = 'uid-1'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals("Ada Lovelace", cursor.getString(cursor.getColumnIndexOrThrow("fn")))
        }

        migrated.execSQL("INSERT INTO `groups` (id, name, rev) VALUES ('group-1', 'Work', 3)")
        migrated.query("SELECT * FROM `groups` WHERE id = 'group-1'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals("Work", cursor.getString(cursor.getColumnIndexOrThrow("name")))
            assertEquals(3L, cursor.getLong(cursor.getColumnIndexOrThrow("rev")))
        }

        migrated.execSQL("INSERT INTO `group_links` (groupId, androidGroupRowId) VALUES ('group-1', 42)")
        migrated.query("SELECT * FROM `group_links` WHERE groupId = 'group-1'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals(42L, cursor.getLong(cursor.getColumnIndexOrThrow("androidGroupRowId")))
        }
    }

    @Test
    fun migrate5To6_addsIsSelfColumn_andPreservesExistingRow() {
        helper.createDatabase(TEST_DB, 5).apply {
            execSQL(
                "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson) " +
                    "VALUES ('uid-1', 1, 'Ada Lovelace', '[]', '[]', '[]')",
            )
            close()
        }

        val migrated = helper.runMigrationsAndValidate(TEST_DB, 6, true, AppDatabase.MIGRATION_5_6)

        migrated.query("SELECT * FROM contacts WHERE uid = 'uid-1'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals("Ada Lovelace", cursor.getString(cursor.getColumnIndexOrThrow("fn")))
            assertEquals(0, cursor.getInt(cursor.getColumnIndexOrThrow("isSelf")))
        }
    }

    @Test
    fun migrate7To8_addsPgpColumns_andDefaultsExistingRowToNoPgp() {
        helper.createDatabase(TEST_DB, 7).apply {
            // Every NOT NULL column in the v7 `emails` schema has to be supplied: none of them
            // carries a SQL default, so a partial INSERT fails with SQLITE_CONSTRAINT_NOTNULL and
            // the migration below is never reached.
            execSQL(
                "INSERT INTO emails " +
                    "(messageId, folder, sender, sentTo, cc, bcc, subject, preview, label, " +
                    "keywordsJson, status, hasAttachments, sourceMode) " +
                    "VALUES ('42', 'INBOX', 'a@example.com', '', '', '', 'Hello', '', '', " +
                    "'[]', 'unread', 0, 'relay')",
            )
            close()
        }

        val migrated = helper.runMigrationsAndValidate(TEST_DB, 8, true, AppDatabase.MIGRATION_7_8)

        migrated.query("SELECT * FROM emails WHERE messageId = '42'").use { cursor ->
            assertEquals(1, cursor.count)
            assertEquals(true, cursor.moveToFirst())
            assertEquals("Hello", cursor.getString(cursor.getColumnIndexOrThrow("subject")))
            // An already-cached row must land as "no OpenPGP content", which is
            // the only state this app has ever rendered it in — not as encrypted,
            // which would hide a body the user could previously read.
            assertEquals(0, cursor.getInt(cursor.getColumnIndexOrThrow("pgpEncrypted")))
            assertEquals(0, cursor.getInt(cursor.getColumnIndexOrThrow("pgpSigned")))
            assertEquals(0, cursor.getInt(cursor.getColumnIndexOrThrow("pgpVerified")))
            assertEquals("", cursor.getString(cursor.getColumnIndexOrThrow("pgpSignerFingerprint")))
            assertEquals("", cursor.getString(cursor.getColumnIndexOrThrow("pgpDecryptError")))
        }
    }

    @Test
    fun migrate8To9_createsContactSyncStateTable() {
        helper.createDatabase(TEST_DB, 8).close()

        val migrated = helper.runMigrationsAndValidate(TEST_DB, 9, true, AppDatabase.MIGRATION_8_9)

        migrated.execSQL("INSERT INTO contact_sync_state (subscriberId, cursor) VALUES ('sub-1', 42)")
        migrated.query("SELECT cursor FROM contact_sync_state WHERE subscriberId = 'sub-1'").use { cursor ->
            assertEquals(true, cursor.moveToFirst())
            assertEquals(42L, cursor.getLong(cursor.getColumnIndexOrThrow("cursor")))
        }
    }

    private companion object {
        const val TEST_DB = "migration-test"
    }
}
