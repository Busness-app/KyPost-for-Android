package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Test

class AttachmentActionTest {
    @Test
    fun forSettings_viewsEphemerally_whenProtectionEnabled() {
        assertEquals(AttachmentAction.VIEW_EPHEMERAL, attachmentActionFor(hostileLocationProtectionEnabled = true))
    }

    @Test
    fun forSettings_savesToDownloads_whenProtectionDisabled() {
        assertEquals(AttachmentAction.SAVE_TO_DOWNLOADS, attachmentActionFor(hostileLocationProtectionEnabled = false))
    }
}
