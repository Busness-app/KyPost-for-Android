package org.kysecurity.mail.contacts.device

import java.time.Instant

enum class Winner {
    ROOM, DEVICE, TIE_PREFER_ROOM
}

object DeviceContactConflictResolver {
    fun parseIso(isoString: String?): Long? {
        if (isoString.isNullOrEmpty()) return null
        return runCatching {
            Instant.parse(isoString).toEpochMilli()
        }.getOrNull()
    }

    fun resolve(
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): Winner {
        return when {
            roomUpdatedAtEpochMs == null && deviceUpdatedAtEpochMs == null -> Winner.TIE_PREFER_ROOM
            roomUpdatedAtEpochMs == null -> Winner.DEVICE
            deviceUpdatedAtEpochMs == null -> Winner.ROOM
            roomUpdatedAtEpochMs > deviceUpdatedAtEpochMs -> Winner.ROOM
            deviceUpdatedAtEpochMs > roomUpdatedAtEpochMs -> Winner.DEVICE
            else -> Winner.TIE_PREFER_ROOM
        }
    }
}
