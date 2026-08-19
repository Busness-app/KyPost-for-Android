package org.kysecurity.mail.pgp

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.data.DataRuntime

internal class RoomLocalSignerKeys(context: Context) : LocalSignerKeyLookup {
    private val appContext = context.applicationContext

    override suspend fun keysFor(address: String): List<LocalSignerKey> {
        val needle = address.trim()
        if (needle.isBlank()) return emptyList()
        return withContext(Dispatchers.IO) {
            val dao = DataRuntime.graph(appContext).database.contactDao()
            // Exact match in Kotlin, not the SQL LIKE: a substring would accept a lookalike.
            dao.search(needle)
                .filter { it.hasEmail(needle) }
                .mapNotNull { it.toLocalSignerKey() }
        }
    }
}

/** Exact, case-insensitive match against a DECODED address. */
internal fun ContactEntity.hasEmail(address: String): Boolean =
    runCatching { toDto().emails.any { it.value.trim().equals(address, ignoreCase = true) } }
        .getOrDefault(false)

/** Alarms clear `confirmed` but still return the key, so a foreign signature reads KEY_CHANGED. */
internal fun ContactEntity.toLocalSignerKey(): LocalSignerKey? {
    val key = pgpKey?.takeIf { it.isNotBlank() } ?: return null
    if (pgpKeyFingerprint.isNullOrBlank()) return null
    return LocalSignerKey(
        publicKey = key,
        confirmed = !pgpKeyNeedsReverification && !identityNeedsReview,
    )
}
