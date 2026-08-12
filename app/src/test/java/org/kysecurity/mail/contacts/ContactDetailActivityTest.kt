package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Test

/** Covers the pure formatting helpers [ContactDetailActivity] uses to render a contact read-only:
 *  [contactSubtitle], [formatAddress], [urlWithScheme]. Pulled out of the Activity for the same
 *  reason as [mergedContactDto] in `ContactEditActivity` — unit-testable without a Context-backed
 *  Activity. */
class ContactDetailActivityTest {

    // ---- contactSubtitle ----

    @Test
    fun contactSubtitle_titleAndOrg_joinedWithDot() {
        val dto = ContactDto(fn = "Jane", title = "Engineer", org = "Acme Inc")
        assertEquals("Engineer · Acme Inc", contactSubtitle(dto))
    }

    @Test
    fun contactSubtitle_titleOnly() {
        val dto = ContactDto(fn = "Jane", title = "Engineer", org = null)
        assertEquals("Engineer", contactSubtitle(dto))
    }

    @Test
    fun contactSubtitle_orgOnly() {
        val dto = ContactDto(fn = "Jane", title = null, org = "Acme Inc")
        assertEquals("Acme Inc", contactSubtitle(dto))
    }

    @Test
    fun contactSubtitle_neither_isBlank() {
        val dto = ContactDto(fn = "Jane", title = null, org = null)
        assertEquals("", contactSubtitle(dto))
    }

    @Test
    fun contactSubtitle_blankFields_treatedAsAbsent() {
        val dto = ContactDto(fn = "Jane", title = "  ", org = "")
        assertEquals("", contactSubtitle(dto))
    }

    // ---- formatAddress ----

    @Test
    fun formatAddress_allFields() {
        val address = ContactAddressDto(
            street = "123 Main St",
            city = "Springfield",
            region = "IL",
            postalCode = "62704",
            country = "USA",
        )
        assertEquals("123 Main St, Springfield, IL 62704, USA", formatAddress(address))
    }

    @Test
    fun formatAddress_missingRegionAndPostalCode() {
        val address = ContactAddressDto(street = "123 Main St", city = "Springfield", country = "USA")
        assertEquals("123 Main St, Springfield, USA", formatAddress(address))
    }

    @Test
    fun formatAddress_onlyCity_noStrayCommas() {
        val address = ContactAddressDto(city = "Springfield")
        assertEquals("Springfield", formatAddress(address))
    }

    @Test
    fun formatAddress_empty_isBlank() {
        assertEquals("", formatAddress(ContactAddressDto()))
    }

    // ---- urlWithScheme ----

    @Test
    fun urlWithScheme_bareHost_getsHttpsPrefix() {
        assertEquals("https://example.com", urlWithScheme("example.com"))
    }

    @Test
    fun urlWithScheme_alreadyHttps_untouched() {
        assertEquals("https://example.com", urlWithScheme("https://example.com"))
    }

    @Test
    fun urlWithScheme_alreadyHttp_untouched() {
        assertEquals("http://example.com", urlWithScheme("http://example.com"))
    }

    @Test
    fun urlWithScheme_trimsWhitespace() {
        assertEquals("https://example.com", urlWithScheme("  example.com  "))
    }
}
