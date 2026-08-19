package org.kysecurity.mail.contacts.device

import android.provider.ContactsContract.CommonDataKinds.Event
import android.provider.ContactsContract.CommonDataKinds.Relation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DeviceContactFieldCodingTest {

    @Test
    fun imCustomProtocolLabel_knownServices_mapToDisplayNames() {
        assertEquals("WhatsApp", DeviceContactFieldCoding.imCustomProtocolLabel("whatsapp", null))
        assertEquals("Signal", DeviceContactFieldCoding.imCustomProtocolLabel("signal", null))
        assertEquals("Telegram", DeviceContactFieldCoding.imCustomProtocolLabel("telegram", null))
        assertEquals("Instagram", DeviceContactFieldCoding.imCustomProtocolLabel("instagram", null))
        assertEquals("X (Twitter)", DeviceContactFieldCoding.imCustomProtocolLabel("x", null))
        assertEquals("LinkedIn", DeviceContactFieldCoding.imCustomProtocolLabel("linkedin", null))
        assertEquals("Facebook", DeviceContactFieldCoding.imCustomProtocolLabel("facebook", null))
        assertEquals("Mastodon", DeviceContactFieldCoding.imCustomProtocolLabel("mastodon", null))
        assertEquals("Matrix", DeviceContactFieldCoding.imCustomProtocolLabel("matrix", null))
    }

    @Test
    fun imCustomProtocolLabel_otherService_usesFreeTextLabel() {
        assertEquals("Discord", DeviceContactFieldCoding.imCustomProtocolLabel("", "Discord"))
        assertEquals("Discord", DeviceContactFieldCoding.imCustomProtocolLabel(null, "Discord"))
    }

    @Test
    fun imCustomProtocolLabel_otherServiceNoLabel_fallsBackToOther() {
        assertEquals("Other", DeviceContactFieldCoding.imCustomProtocolLabel("", null))
        assertEquals("Other", DeviceContactFieldCoding.imCustomProtocolLabel("", ""))
        assertEquals("Other", DeviceContactFieldCoding.imCustomProtocolLabel(null, null))
    }

    @Test
    fun imCustomProtocolLabel_unrecognizedService_fallsBackToLabelThenOther() {
        assertEquals("Old Network", DeviceContactFieldCoding.imCustomProtocolLabel("icq", "Old Network"))
        assertEquals("Other", DeviceContactFieldCoding.imCustomProtocolLabel("icq", null))
    }

    @Test
    fun imServiceFromCustomProtocolLabel_knownDisplayNames_roundTripToServiceCodes() {
        val services = listOf(
            "whatsapp", "signal", "telegram", "instagram", "x",
            "linkedin", "facebook", "mastodon", "matrix",
        )
        for (service in services) {
            val displayLabel = DeviceContactFieldCoding.imCustomProtocolLabel(service, null)
            assertEquals(
                service,
                DeviceContactFieldCoding.imServiceFromCustomProtocolLabel(displayLabel),
                "round-trip failed for service '$service' (display label '$displayLabel')",
            )
        }
    }

    @Test
    fun imServiceFromCustomProtocolLabel_unrecognizedLabel_fallsBackToOther() {
        assertEquals("", DeviceContactFieldCoding.imServiceFromCustomProtocolLabel("Discord"))
        assertEquals("", DeviceContactFieldCoding.imServiceFromCustomProtocolLabel("Other"))
        assertEquals("", DeviceContactFieldCoding.imServiceFromCustomProtocolLabel(null))
        assertEquals("", DeviceContactFieldCoding.imServiceFromCustomProtocolLabel(""))
    }

    @Test
    fun relationType_knownLabels_mapToClosestConstant() {
        assertEquals(Relation.TYPE_SPOUSE, DeviceContactFieldCoding.relationType("spouse"))
        assertEquals(Relation.TYPE_CHILD, DeviceContactFieldCoding.relationType("child"))
        assertEquals(Relation.TYPE_PARENT, DeviceContactFieldCoding.relationType("parent"))
        assertEquals(Relation.TYPE_PARTNER, DeviceContactFieldCoding.relationType("partner"))
        assertEquals(Relation.TYPE_MANAGER, DeviceContactFieldCoding.relationType("manager"))
        assertEquals(Relation.TYPE_ASSISTANT, DeviceContactFieldCoding.relationType("assistant"))
        assertEquals(Relation.TYPE_FRIEND, DeviceContactFieldCoding.relationType("friend"))
        assertEquals(Relation.TYPE_RELATIVE, DeviceContactFieldCoding.relationType("relative"))
    }

    @Test
    fun relationType_otherOrUnrecognized_fallsBackToCustom() {
        assertEquals(Relation.TYPE_CUSTOM, DeviceContactFieldCoding.relationType("other"))
        assertEquals(Relation.TYPE_CUSTOM, DeviceContactFieldCoding.relationType("colleague"))
        assertEquals(Relation.TYPE_CUSTOM, DeviceContactFieldCoding.relationType(null))
    }

    @Test
    fun relationCustomLabel_onlySetForCustomType() {
        assertNull(DeviceContactFieldCoding.relationCustomLabel("spouse"))
        assertEquals("other", DeviceContactFieldCoding.relationCustomLabel("other"))
        assertEquals("colleague", DeviceContactFieldCoding.relationCustomLabel("colleague"))
    }

    @Test
    fun eventType_anniversary_mapsToAnniversaryConstant() {
        assertEquals(Event.TYPE_ANNIVERSARY, DeviceContactFieldCoding.eventType("anniversary"))
    }

    @Test
    fun eventType_anythingElse_fallsBackToCustom() {
        assertEquals(Event.TYPE_CUSTOM, DeviceContactFieldCoding.eventType("work-start"))
        assertEquals(Event.TYPE_CUSTOM, DeviceContactFieldCoding.eventType(null))
    }

    @Test
    fun eventCustomLabel_onlySetForCustomType() {
        assertNull(DeviceContactFieldCoding.eventCustomLabel("anniversary"))
        assertEquals("work-start", DeviceContactFieldCoding.eventCustomLabel("work-start"))
    }

    @Test
    fun relationLabelFromType_knownConstants_mapBackToVocabulary() {
        assertEquals("spouse", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_SPOUSE))
        assertEquals("child", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_CHILD))
        assertEquals("parent", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_PARENT))
        assertEquals("partner", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_PARTNER))
        assertEquals("manager", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_MANAGER))
        assertEquals("assistant", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_ASSISTANT))
        assertEquals("friend", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_FRIEND))
        assertEquals("relative", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_RELATIVE))
    }

    @Test
    fun relationLabelFromType_customOrUnrecognized_fallsBackToOther() {
        assertEquals("other", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_CUSTOM))
        assertEquals("other", DeviceContactFieldCoding.relationLabelFromType(Relation.TYPE_BROTHER))
        assertEquals("other", DeviceContactFieldCoding.relationLabelFromType(null))
    }

    @Test
    fun eventLabelFromType_anniversaryConstant_mapsBackToAnniversary() {
        assertEquals("anniversary", DeviceContactFieldCoding.eventLabelFromType(Event.TYPE_ANNIVERSARY))
    }

    @Test
    fun eventLabelFromType_anythingElse_returnsNull() {
        assertNull(DeviceContactFieldCoding.eventLabelFromType(Event.TYPE_CUSTOM))
        assertNull(DeviceContactFieldCoding.eventLabelFromType(Event.TYPE_OTHER))
        assertNull(DeviceContactFieldCoding.eventLabelFromType(null))
    }
}
