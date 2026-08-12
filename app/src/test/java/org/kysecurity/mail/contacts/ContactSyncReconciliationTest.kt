package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.PendingContactChangeEntity
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactSyncReconciliationTest {
    private val json = Json { ignoreUnknownKeys = true }

    private fun pendingCreate(localUid: String, dto: ContactDto): PendingContactChangeEntity =
        PendingContactChangeEntity(
            localUid = localUid,
            rev = 0,
            changeType = ContactSyncRepository.CHANGE_CREATE,
            payloadJson = json.encodeToString(dto),
            createdAtEpochMs = 0L,
        )

    @Test
    fun reconcile_matchesSingleCreateByContent() {
        val pending = pendingCreate("temp-1", ContactDto(fn = "Grace Hopper", org = "US Navy"))
        val changed = listOf(ContactDto(uid = "server-1", rev = 1, fn = "Grace Hopper", org = "US Navy"))

        val result = ContactSyncReconciliation.reconcile(listOf(pending), changed)

        assertEquals(mapOf("temp-1" to "server-1"), result)
    }

    @Test
    fun reconcile_ignoresUnrelatedChangedEntries() {
        val pending = pendingCreate("temp-1", ContactDto(fn = "Ada Lovelace"))
        val changed = listOf(
            ContactDto(uid = "server-9", rev = 4, fn = "Someone Else"),
            ContactDto(uid = "server-1", rev = 1, fn = "Ada Lovelace"),
        )

        val result = ContactSyncReconciliation.reconcile(listOf(pending), changed)

        assertEquals(mapOf("temp-1" to "server-1"), result)
    }

    @Test
    fun reconcile_doesNotDoubleClaimTheSameChangedEntry() {
        val pendingA = pendingCreate("temp-a", ContactDto(fn = "Same Name"))
        val pendingB = pendingCreate("temp-b", ContactDto(fn = "Same Name"))
        val changed = listOf(ContactDto(uid = "server-1", rev = 1, fn = "Same Name"))

        val result = ContactSyncReconciliation.reconcile(listOf(pendingA, pendingB), changed)

        assertEquals(1, result.size)
        assertTrue(result.containsKey("temp-a"))
    }

    @Test
    fun reconcile_noMatchLeavesCreateUnreconciled() {
        val pending = pendingCreate("temp-1", ContactDto(fn = "No Match Here"))
        val changed = listOf(ContactDto(uid = "server-1", rev = 1, fn = "Different Name"))

        val result = ContactSyncReconciliation.reconcile(listOf(pending), changed)

        assertTrue(result.isEmpty())
    }

    @Test
    fun reconcile_emptyInputsReturnEmptyMap() {
        assertTrue(ContactSyncReconciliation.reconcile(emptyList(), emptyList()).isEmpty())
    }
}
