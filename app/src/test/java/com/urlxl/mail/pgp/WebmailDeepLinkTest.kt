package com.urlxl.mail.pgp

import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Test

class WebmailDeepLinkTest {

    @Test
    fun buildsReadRouteWithMessageParam() {
        assertEquals(
            "https://mail.example.com/read?mailbox=Archive&message=42",
            webmailMessageUrl("https://mail.example.com", "Archive", "42"),
        )
    }

    @Test
    fun toleratesTrailingSlashOnServerUrl() {
        assertEquals(
            "https://mail.example.com/read?mailbox=Archive&message=42",
            webmailMessageUrl("https://mail.example.com/", "Archive", "42"),
        )
    }

    /** The web app's own Inbox link is a bare /read, and ReadPage treats an absent mailbox as the
     *  default — so sending the literal "INBOX" would diverge from every link the server builds. */
    @Test
    fun inboxIsSentAsAnAbsentMailboxParam() {
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "INBOX", "42"),
        )
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "inbox", "42"),
        )
        assertEquals(
            "https://mail.example.com/read?message=42",
            webmailMessageUrl("https://mail.example.com", "", "42"),
        )
    }

    @Test
    fun encodesMailboxNamesWithSpacesAndSlashes() {
        val url = webmailMessageUrl("https://mail.example.com", "Clients/Acme Corp", "7")
        assertTrue(url!!.contains("mailbox=Clients%2FAcme%20Corp"), "unexpected encoding: $url")
    }

    @Test
    fun portAndSubpathAreOnTheServerUrlNotAssumed() {
        assertEquals(
            "https://mail.example.com:8443/read?message=9",
            webmailMessageUrl("https://mail.example.com:8443", "INBOX", "9"),
        )
    }

    /** Null means "render no button" — a dead button is worse than none. */
    @Test
    fun unusableInputsReturnNull() {
        assertNull(webmailMessageUrl("not a url", "INBOX", "42"))
        assertNull(webmailMessageUrl("", "INBOX", "42"))
        assertNull(webmailMessageUrl("https://mail.example.com", "INBOX", ""))
    }
}
