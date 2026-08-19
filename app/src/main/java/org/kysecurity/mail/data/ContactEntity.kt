package org.kysecurity.mail.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

// The @ColumnInfo defaults exist because MIGRATION_3_4 added those NOT NULL columns by ALTER TABLE.
@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey val uid: String,
    val rev: Long,
    val createdAt: String? = null,
    val updatedAt: String? = null,
    val fn: String,
    val givenName: String? = null,
    val familyName: String? = null,
    val middleName: String? = null,
    val prefix: String? = null,
    val suffix: String? = null,
    val nickname: String? = null,
    val org: String? = null,
    val title: String? = null,
    val notes: String? = null,
    val birthday: String? = null,
    val emailsJson: String = "[]",
    val phonesJson: String = "[]",
    val addressesJson: String = "[]",
    @ColumnInfo(defaultValue = "[]") val groupIDsJson: String = "[]",
    val photoRef: String? = null,
    val pgpKey: String? = null,
    @ColumnInfo(defaultValue = "[]") val imsJson: String = "[]",
    @ColumnInfo(defaultValue = "[]") val websitesJson: String = "[]",
    @ColumnInfo(defaultValue = "[]") val relationsJson: String = "[]",
    @ColumnInfo(defaultValue = "[]") val eventsJson: String = "[]",
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
    @ColumnInfo(defaultValue = "[]") val customFieldsJson: String = "[]",
    val pronouns: String? = null,
    @ColumnInfo(defaultValue = "0") val isSelf: Boolean = false,
    // Computed locally (PgpFingerprint.compute); never server-supplied, never synced back.
    val pgpKeyFingerprint: String? = null,
    @ColumnInfo(defaultValue = "0") val pgpKeyNeedsReverification: Boolean = false,
    @ColumnInfo(defaultValue = "0") val identityNeedsReview: Boolean = false,
)
