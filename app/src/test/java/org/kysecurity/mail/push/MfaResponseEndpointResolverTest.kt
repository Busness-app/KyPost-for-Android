package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Test

class MfaResponseEndpointResolverTest {

    @Test
    fun resolve_trimsTrailingSlash() {
        assertEquals(
            "https://mail.example.com/api/mfa/push/respond",
            resolveMfaRespondEndpoint("https://mail.example.com/"),
        )
    }

    @Test
    fun resolve_noTrailingSlash_isUnchanged() {
        assertEquals(
            "https://mail.example.com/api/mfa/push/respond",
            resolveMfaRespondEndpoint("https://mail.example.com"),
        )
    }
}
