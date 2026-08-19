package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttachmentActionTest {

    @Test
    fun savingIsOfferedOnlyWithProtectionOff() {
        assertTrue(attachmentSaveOffered(hostileLocationProtectionEnabled = false))
        assertFalse(attachmentSaveOffered(hostileLocationProtectionEnabled = true))
    }
}
