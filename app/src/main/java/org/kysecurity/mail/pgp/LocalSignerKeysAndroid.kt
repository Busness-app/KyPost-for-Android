package org.kysecurity.mail.pgp

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.data.DataRuntime

/**
 * The Room-backed [LocalSignerKeyLookup] — this device's own answer to "whose key is this",
 * assembled from the contact store rather than from the relay's response.
 *
 * Separate file from [SignerBinding] for the same reason [EnrollmentPortsAndroid] is separate from
 * [EnrollmentPorts]: everything the verdict logic itself touches stays free of Android and of Room,
 * so it can be exercised by a JVM test, and the framework lives out here.
 */
internal class RoomLocalSignerKeys(context: Context) : LocalSignerKeyLookup {
    private val appContext = context.applicationContext

    override suspend fun keysFor(address: String): List<LocalSignerKey> {
        val needle = address.trim()
        if (needle.isBlank()) return emptyList()
        return withContext(Dispatchers.IO) {
            val dao = DataRuntime.graph(appContext).database.contactDao()
            // The LIKE narrows in SQL; the exact match happens in Kotlin against the DECODED
            // addresses. Matching the raw emailsJson alone would accept `bob@example.com` for a
            // contact whose stored address is `notbob@example.com.evil.tld`, which is a substring
            // of it — fine for autocomplete, which is what that query was built for, and not fine
            // for the input to a trust decision.
            dao.search(needle)
                .filter { it.hasEmail(needle) }
                .mapNotNull { it.toLocalSignerKey() }
        }
    }
}

/** Exact, case-insensitive match against a DECODED address. `internal` rather than private so
 *  the two decisions this file actually makes have a JVM test — neither needs Room, and requiring
 *  an emulator to assert "is a substring an address" is how that assertion never gets written. */
internal fun ContactEntity.hasEmail(address: String): Boolean =
    runCatching { toDto().emails.any { it.value.trim().equals(address, ignoreCase = true) } }
        .getOrDefault(false)

/**
 * A contact row as a signer key, or null when the row carries nothing this device can vouch for.
 *
 * [LocalSignerKey.confirmed] requires all three: a key, a locally-computed fingerprint, and neither
 * alarm outstanding.
 *
 * - `pgpKeyFingerprint` non-null means [PgpFingerprint.compute] accepted the blob — which is what
 *   rejects an appended second key ring and an unbound subkey. A row whose fingerprint is null is
 *   holding a key the local parser refused to vouch for, so it is not offered at all.
 * - `pgpKeyNeedsReverification` is the key alarm: the fingerprint changed under a contact that had
 *   one, or the blob stopped parsing.
 * - `identityNeedsReview` is the identity alarm: same key, different addresses beside it. The QR
 *   ceremony deliberately cannot clear this one, so it must gate the badge the ceremony grants.
 *
 * A row that fails only the alarms still returns a key — with `confirmed = false`. That is not a
 * softening: [signatureStateFor] treats a locally-held key as authoritative about *which* key the
 * sender uses regardless, so returning it is what makes a signature by some other key report
 * KEY_CHANGED instead of falling through to the relay's opinion.
 */
internal fun ContactEntity.toLocalSignerKey(): LocalSignerKey? {
    val key = pgpKey?.takeIf { it.isNotBlank() } ?: return null
    if (pgpKeyFingerprint.isNullOrBlank()) return null
    return LocalSignerKey(
        publicKey = key,
        confirmed = !pgpKeyNeedsReverification && !identityNeedsReview,
    )
}
