package org.kysecurity.mail

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SettingsSupportDestinationTest {
    @Test
    fun playUsesBillingWhileSideloadBuildsUseBuyMeACoffee() {
        assertNull(supportUrlForFlavor("play"))
        assertEquals(
            "https://buymeacoffee.com/yoshiofthewire",
            supportUrlForFlavor("fdroid"),
        )
        assertEquals(
            "https://buymeacoffee.com/yoshiofthewire",
            supportUrlForFlavor("github"),
        )
    }
}
