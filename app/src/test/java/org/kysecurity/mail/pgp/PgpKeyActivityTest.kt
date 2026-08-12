package org.kysecurity.mail.pgp

import org.kysecurity.mail.contacts.ContactFieldDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Covers [PgpKeyActivity.parsePgpQrKeyUrl] — a pure function with no Android framework
 *  dependency, so it's plain-JVM testable like [PgpQrClientTest]'s coverage of [PgpQrClient]. No
 *  mocking framework, matching this repo's house style. */
class PgpKeyActivityTest {

    @Test
    fun parsePgpQrKeyUrl_validUrl_extractsServerUrlAndToken() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key?t=abc123",
        )

        assertEquals(ParsedPgpQrKeyUrl(serverUrl = "https://mail.example.com", token = "abc123"), parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_malformedString_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl("not a url at all")

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_wrongPath_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/token?t=abc123",
        )

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_missingTParam_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key",
        )

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_blankTParam_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key?t=",
        )

        assertNull(parsed)
    }

    @Test
    fun contactDtoFromCard_mapsAllFields() {
        val card = PgpQrContactCardDto(
            fn = "Alice Example",
            givenName = "Alice",
            familyName = "Example",
            org = "Example Corp",
            title = "Engineer",
            emails = listOf(ContactFieldDto(label = "work", value = "alice@example.com")),
            phones = listOf(ContactFieldDto(value = "+1-555-0100")),
            notes = "Met at conference",
            pronouns = "she/her",
        )

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "Alice", pgpKey = "PUBKEY")

        assertEquals("Alice Example", dto.fn)
        assertEquals("Alice", dto.givenName)
        assertEquals("Example", dto.familyName)
        assertEquals("Example Corp", dto.org)
        assertEquals("Engineer", dto.title)
        assertEquals("alice@example.com", dto.emails.single().value)
        assertEquals("+1-555-0100", dto.phones.single().value)
        assertEquals("Met at conference", dto.notes)
        assertEquals("she/her", dto.pronouns)
        assertEquals("PUBKEY", dto.pgpKey)
    }

    @Test
    fun contactDtoFromCard_blankCardName_fallsBackToScannedName() {
        val card = PgpQrContactCardDto(fn = null)

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "Alice", pgpKey = "PUBKEY")

        assertEquals("Alice", dto.fn)
    }

    @Test
    fun contactDtoFromCard_blankCardNameAndBlankFallback_usesUnknown() {
        val card = PgpQrContactCardDto(fn = null)

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "", pgpKey = "PUBKEY")

        assertEquals("Unknown", dto.fn)
    }
}
