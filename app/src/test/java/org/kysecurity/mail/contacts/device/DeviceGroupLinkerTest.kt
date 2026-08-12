package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.data.GroupEntity
import org.kysecurity.mail.data.GroupLinkEntity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Covers [findExistingGroupRowId], the pure find-by-title decision [DeviceGroupLinker] uses to
 *  avoid duplicating an on-device group the user already has — the class itself needs a real
 *  `ContentResolver`/`AppDatabase` so isn't directly unit-testable in this repo's no-Robolectric
 *  JVM test setup (same gap `ContactSyncRepositoryTest.kt` documents for `ContactSyncRepository`).
 *  Also covers [groupRenameTargets], the pure join [DeviceContactRepository] uses to detect which
 *  *already-linked* groups need a rename pass on every sync cycle (not just newly-created
 *  contacts) — the fix for the plan's Part 2 point 4 gap. */
class DeviceGroupLinkerTest {
    @Test
    fun findExistingGroupRowId_noGroups_returnsNull() {
        assertNull(findExistingGroupRowId(emptyList(), "Work"))
    }

    @Test
    fun findExistingGroupRowId_matchingTitle_returnsItsRowId() {
        val existing = listOf(1L to "Family", 2L to "Work")
        assertEquals(2L, findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun findExistingGroupRowId_noMatchingTitle_returnsNull() {
        val existing = listOf(1L to "Family", 2L to "Work")
        assertNull(findExistingGroupRowId(existing, "Friends"))
    }

    @Test
    fun findExistingGroupRowId_isCaseSensitive() {
        val existing = listOf(1L to "work")
        assertNull(findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun findExistingGroupRowId_firstMatchWins() {
        val existing = listOf(1L to "Work", 2L to "Work")
        assertEquals(1L, findExistingGroupRowId(existing, "Work"))
    }

    @Test
    fun groupRenameTargets_noLinks_returnsEmpty() {
        val groups = listOf(GroupEntity(id = "g1", name = "Work", rev = 2))
        assertTrue(groupRenameTargets(emptyList(), groups).isEmpty())
    }

    @Test
    fun groupRenameTargets_linkedGroupRenamedOnBackend_returnsAndroidRowIdWithFreshName() {
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 42L))
        val groups = listOf(GroupEntity(id = "g1", name = "Work Squad", rev = 3))
        assertEquals(listOf(42L to "Work Squad"), groupRenameTargets(links, groups))
    }

    @Test
    fun groupRenameTargets_linkedGroupNameUnchanged_stillReturnsPair() {
        // groupRenameTargets always resolves the current fresh name for every existing link --
        // whether that name actually differs from the on-device title is decided later by
        // DeviceGroupLinker.renameIfNeeded's own ContentResolver query, not here.
        val links = listOf(GroupLinkEntity(groupId = "g1", androidGroupRowId = 42L))
        val groups = listOf(GroupEntity(id = "g1", name = "Work", rev = 1))
        assertEquals(listOf(42L to "Work"), groupRenameTargets(links, groups))
    }

    @Test
    fun groupRenameTargets_linkToDeletedBackendGroup_isSkipped() {
        // The group was removed from the backend (and thus from GroupSyncRepository's refreshed
        // GroupEntity cache) but the link row is still present -- nothing to rename to.
        val links = listOf(GroupLinkEntity(groupId = "gone", androidGroupRowId = 99L))
        assertTrue(groupRenameTargets(links, emptyList()).isEmpty())
    }

    @Test
    fun groupRenameTargets_multipleLinks_resolvesEachIndependently() {
        val links = listOf(
            GroupLinkEntity(groupId = "g1", androidGroupRowId = 1L),
            GroupLinkEntity(groupId = "g2", androidGroupRowId = 2L),
            GroupLinkEntity(groupId = "gone", androidGroupRowId = 3L),
        )
        val groups = listOf(
            GroupEntity(id = "g1", name = "Family", rev = 1),
            GroupEntity(id = "g2", name = "Work Squad", rev = 5),
        )
        assertEquals(
            listOf(1L to "Family", 2L to "Work Squad"),
            groupRenameTargets(links, groups),
        )
    }
}
