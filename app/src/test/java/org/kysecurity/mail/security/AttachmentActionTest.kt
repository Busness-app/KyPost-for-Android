package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttachmentActionTest {

    @Test
    fun tappingAnAttachmentViewsItEphemerallyWithProtectionOn() {
        assertEquals(AttachmentAction.VIEW_EPHEMERAL, attachmentActionFor(hostileLocationProtectionEnabled = true))
    }

    @Test
    fun tappingAnAttachmentViewsItEphemerallyWithProtectionOffToo() {
        assertEquals(AttachmentAction.VIEW_EPHEMERAL, attachmentActionFor(hostileLocationProtectionEnabled = false))
    }

    @Test
    fun savingIsOfferedOnlyWithProtectionOff() {
        assertTrue(attachmentSaveOffered(hostileLocationProtectionEnabled = false))
        assertFalse(attachmentSaveOffered(hostileLocationProtectionEnabled = true))
    }
}
