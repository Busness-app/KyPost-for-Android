package com.urlxl.mail.pgp

import com.urlxl.mail.mail.ClientEncryptedMessage
import com.urlxl.mail.mail.MailOutcome
import com.urlxl.mail.mail.MailSendOutcome

internal class FakeRecipientKeyResolver(
    var result: ResolveResult = ResolveResult.Success(emptyList()),
) : RecipientKeyResolver {
    var calls = 0
    var lastAddresses: List<String> = emptyList()

    override suspend fun resolve(addresses: List<String>): ResolveResult {
        calls++
        lastAddresses = addresses
        return result
    }
}

internal class FakeClientEncryptedTransport(
    var outcome: MailOutcome<MailSendOutcome> = MailOutcome.Success(MailSendOutcome(true, "")),
) : ClientEncryptedTransport {
    val sent = mutableListOf<ClientEncryptedMessage>()

    override fun send(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> {
        sent += message
        return outcome
    }
}

/** Builds a [ResolveResult.Success] where every address resolves to [publicKey] and is usable. */
internal fun resolvedAll(
    addresses: List<String>,
    publicKey: String,
    tier: String = "contact-verified",
    usable: Boolean = true,
) = ResolveResult.Success(
    addresses.map {
        ResolvedRecipientKey(
            address = it,
            publicKey = publicKey,
            fingerprint = "",
            tier = tier,
            usable = usable,
        )
    },
)

/** Pulls the armored OpenPGP block out of a PGP/MIME delivery, the way a recipient's client does. */
internal fun armorOf(delivery: String): String {
    val end = "-----END PGP MESSAGE-----"
    return delivery.substring(delivery.indexOf("-----BEGIN PGP MESSAGE-----"), delivery.indexOf(end) + end.length)
}
