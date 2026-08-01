package com.urlxl.mail.data

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/** suspend/Flow-based, matching the coroutine convention already used by push/PushRepository. */
@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY isSelf DESC, fn COLLATE NOCASE")
    fun observeAll(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE uid = :uid")
    suspend fun getByUid(uid: String): ContactEntity?

    /** The account owner's own contact. Used to show the user their own PGP fingerprint next to
     *  the QR they present, so the other side's "confirm this matches" has something to match. */
    @Query("SELECT * FROM contacts WHERE isSelf = 1 LIMIT 1")
    suspend fun getSelf(): ContactEntity?

    @Upsert
    suspend fun upsertAll(contacts: List<ContactEntity>)

    @Query("DELETE FROM contacts WHERE uid IN (:uids)")
    suspend fun deleteByUids(uids: List<String>)

    @Query("DELETE FROM contacts")
    suspend fun clearAll()

    /** Name-or-email substring match for the contact-autocomplete feature (spec:
     *  ContactAutocomplete.md). LIKE is case-insensitive for ASCII in SQLite by default, so no
     *  explicit COLLATE NOCASE is needed on the LIKE itself. Matches against the raw
     *  [ContactEntity.emailsJson] string rather than decoding it — the email address appears
     *  verbatim inside the encoded JSON, so a substring match is correct without a JOIN/decode;
     *  see RecipientMatching.kt for why only the *primary* email is ever displayed even though
     *  this query can match on a secondary one. Contacts with no email at all
     *  (`emailsJson = '[]'`) are excluded — nothing to autocomplete to. */
    suspend fun search(query: String): List<ContactEntity> = searchEscaped(query.escapeLikePattern())

    @Query(
        """
        SELECT * FROM contacts
        WHERE (fn LIKE '%' || :query || '%' ESCAPE '\'
            OR emailsJson LIKE '%' || :query || '%' ESCAPE '\')
          AND emailsJson != '[]'
        ORDER BY fn COLLATE NOCASE
        LIMIT 5
        """,
    )
    suspend fun searchEscaped(query: String): List<ContactEntity>
}

internal fun String.escapeLikePattern(): String =
    replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
