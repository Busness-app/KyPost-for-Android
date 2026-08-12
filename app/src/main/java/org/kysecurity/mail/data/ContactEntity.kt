package org.kysecurity.mail.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Mirrors the `Contact` JSON shape in Mobile_Contact_Sync.md. [emailsJson]/[phonesJson]/
 * [addressesJson] hold pre-encoded kotlinx.serialization JSON for the field-entry lists — plain
 * String columns rather than a TypeConverter, since callers already have a Json instance handy
 * from decoding the sync response. The newer list columns ([groupIDsJson], [imsJson],
 * [websitesJson], [relationsJson], [eventsJson], [customFieldsJson]) carry an explicit
 * `@ColumnInfo(defaultValue = "[]")` — unlike the original three, they were added to an
 * already-populated table via [AppDatabase.MIGRATION_3_4], and SQLite requires a NOT NULL
 * column added by ALTER TABLE to declare a default so existing rows stay valid.
 */
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
    // Locally-computed OpenPGP fingerprint of [pgpKey] (see PgpFingerprint.compute) — never
    // trusts a server-supplied fingerprint string, same discipline as the QR key-exchange flow.
    // Used only to detect when a sync-delivered pgpKey silently changes; not synced to the server.
    val pgpKeyFingerprint: String? = null,
    @ColumnInfo(defaultValue = "0") val pgpKeyNeedsReverification: Boolean = false,
    /**
     * The *identity* alarm, kept separate from [pgpKeyNeedsReverification] because they answer
     * different questions and are cleared by different evidence.
     *
     * [pgpKeyNeedsReverification] means "this key changed" and a QR fingerprint comparison answers
     * it. This one means "the addresses this key is displayed beside changed", which a fingerprint
     * comparison says nothing about — the ceremony builds its DTO from the current, possibly already
     * tampered, Room row. With one shared column the ceremony cleared both, so a WRITE_CONTACTS app
     * could rewrite a contact's phone number, the app would raise an alarm reading "Key changed",
     * and the user's obvious remediation — meet them, scan the QR, compare the fingerprint — silently
     * cleared an alarm about an address injection nobody had examined.
     */
    @ColumnInfo(defaultValue = "0") val identityNeedsReview: Boolean = false,
)
