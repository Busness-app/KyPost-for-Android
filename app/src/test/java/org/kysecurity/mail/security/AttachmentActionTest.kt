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

    /**
     * The regression this exists for: a tap used to mean SAVE_TO_DOWNLOADS whenever protection was
     * off, which is the default. One unprompted tap therefore wrote decrypted mail into shared
     * storage outside the sandbox, and [EphemeralAttachmentBytes] — the whole TTL-and-zeroing
     * apparatus — was unreachable for almost every user.
     */
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
