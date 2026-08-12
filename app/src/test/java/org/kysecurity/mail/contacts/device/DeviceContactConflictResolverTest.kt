package org.kysecurity.mail.contacts.device

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DeviceContactConflictResolverTest {
    @Test
    fun parseIsoValidTimestamp() {
        val ms = DeviceContactConflictResolver.parseIso("2026-01-15T10:30:00Z")
        assertEquals(1768473000000L, ms)
    }

    @Test
    fun parseIsoNullOrEmpty() {
        assertNull(DeviceContactConflictResolver.parseIso(null))
        assertNull(DeviceContactConflictResolver.parseIso(""))
    }

    @Test
    fun parseIsoMalformed() {
        assertNull(DeviceContactConflictResolver.parseIso("not-a-date"))
    }

    @Test
    fun resolveBothNull() {
        assertEquals(Winner.TIE_PREFER_ROOM, DeviceContactConflictResolver.resolve(null, null))
    }

    @Test
    fun resolveRoomNullDeviceSet() {
        assertEquals(Winner.DEVICE, DeviceContactConflictResolver.resolve(null, 100L))
    }

    @Test
    fun resolveRoomSetDeviceNull() {
        assertEquals(Winner.ROOM, DeviceContactConflictResolver.resolve(100L, null))
    }

    @Test
    fun resolveRoomNewer() {
        assertEquals(Winner.ROOM, DeviceContactConflictResolver.resolve(200L, 100L))
    }

    @Test
    fun resolveDeviceNewer() {
        assertEquals(Winner.DEVICE, DeviceContactConflictResolver.resolve(100L, 200L))
    }

    @Test
    fun resolveTiePreferRoom() {
        assertEquals(Winner.TIE_PREFER_ROOM, DeviceContactConflictResolver.resolve(100L, 100L))
    }
}
