package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HostileLocationSettingsTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Before
    fun resetState() {
        HostileLocationSettings(context).setEnabled(false)
    }

    @Test
    fun isEnabled_defaultsFalse() {
        assertFalse(HostileLocationSettings(context).isEnabled())
    }

    @Test
    fun setEnabled_persistsAcrossInstances() {
        HostileLocationSettings(context).setEnabled(true)
        assertTrue(HostileLocationSettings(context).isEnabled())
    }
}
