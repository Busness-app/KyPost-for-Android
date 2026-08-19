package org.kysecurity.mail.pgp

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactCustomFieldDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto
import kotlinx.serialization.Serializable

/** Response body of `GET /api/pgp/qr/token` (pairing-authenticated). */
@Serializable
data class PgpQrTokenDto(
    val token: String = "",
    val expiresAt: String = "",
    val url: String = "",
)

/** Response body of `GET /api/pgp/qr/key` (unauthenticated, token-gated). */
@Serializable
data class PgpQrKeyDto(
    val name: String = "",
    val fingerprint: String = "",
    val publicKey: String = "",
    val contactCard: PgpQrContactCardDto? = null,
)

/** Mirrors the server's `pgpQRContactCard` struct (`backend/internal/api/pgp_qr_handlers.go`). */
@Serializable
data class PgpQrContactCardDto(
    val fn: String? = null,
    val givenName: String? = null,
    val familyName: String? = null,
    val middleName: String? = null,
    val prefix: String? = null,
    val suffix: String? = null,
    val nickname: String? = null,
    val org: String? = null,
    val title: String? = null,
    val emails: List<ContactFieldDto> = emptyList(),
    val phones: List<ContactFieldDto> = emptyList(),
    val addresses: List<ContactAddressDto> = emptyList(),
    val notes: String? = null,
    val birthday: String? = null,
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
    val customFields: List<ContactCustomFieldDto> = emptyList(),
    val pronouns: String? = null,
)
