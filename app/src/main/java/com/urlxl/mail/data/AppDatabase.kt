package com.urlxl.mail.data

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        EmailEntity::class,
        FolderEntity::class,
        ContactEntity::class,
        PendingContactChangeEntity::class,
        DeviceContactLinkEntity::class,
        GroupEntity::class,
        GroupLinkEntity::class,
    ],
    version = 8,
    exportSchema = true,
)
@TypeConverters(Converters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun emailDao(): EmailDao
    abstract fun folderDao(): FolderDao
    abstract fun contactDao(): ContactDao
    abstract fun pendingContactChangeDao(): PendingContactChangeDao
    abstract fun deviceContactLinkDao(): DeviceContactLinkDao
    abstract fun groupDao(): GroupDao
    abstract fun groupLinkDao(): GroupLinkDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `device_contact_links` (" +
                        "`uid` TEXT NOT NULL, `rawContactId` INTEGER NOT NULL, " +
                        "`deviceUpdatedAtEpochMs` INTEGER NOT NULL, PRIMARY KEY(`uid`))",
                )
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `emails` ADD COLUMN `hasAttachments` INTEGER NOT NULL DEFAULT 0",
                )
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `groupIDsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `photoRef` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKey` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `imsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `websitesJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `relationsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `eventsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `phoneticGivenName` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `phoneticFamilyName` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `department` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `customFieldsJson` TEXT NOT NULL DEFAULT '[]'")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pronouns` TEXT")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `groups` (" +
                        "`id` TEXT NOT NULL, `name` TEXT NOT NULL, `rev` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `group_links` (" +
                        "`groupId` TEXT NOT NULL, `androidGroupRowId` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`groupId`))",
                )
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `isSelf` INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKeyFingerprint` TEXT")
                db.execSQL("ALTER TABLE `contacts` ADD COLUMN `pgpKeyNeedsReverification` INTEGER NOT NULL DEFAULT 0")
            }
        }

        // Defaults match a message with no OpenPGP content, which is what every
        // already-cached row is as far as this app has ever known — so existing
        // rows land in exactly the state they were already being rendered in.
        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpEncrypted` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpSigned` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpVerified` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpSignerFingerprint` TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE `emails` ADD COLUMN `pgpDecryptError` TEXT NOT NULL DEFAULT ''")
            }
        }
    }
}
