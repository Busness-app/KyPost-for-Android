package org.kysecurity.mail.pgp

import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ACCOUNT = "me@example.invalid"

class ClientEncryptedSenderTest {

    @After
    fun clearHeldKey() = EnrollmentSession.clear()

    private fun sender(
        opener: FakeVaultOpener = FakeVaultOpener(),
        resolver: FakeRecipientKeyResolver = FakeRecipientKeyResolver(),
        transport: FakeClientEncryptedTransport = FakeClientEncryptedTransport(),
        accountAddress: String = ACCOUNT,
    ) = ClientEncryptedSender(
        opener = opener,
        resolver = resolver,
        transport = transport,
        accountAddress = accountAddress,
    )

    private fun draft(to: String = "alice@example.invalid", cc: String = "", bcc: String = "") =
        MailDraft(to = to, cc = cc, bcc = bcc, subject = "Subject", body = "<p>Body</p>", mode = "html")

    /**
     * To and CC share one ciphertext; every BCC recipient gets their own.
     *
     * This is the whole reason `deliveries` is a list. One shared ciphertext would put each BCC
     * recipient's key id in a packet every other recipient can read — which is exactly the thing
     * BCC promises not to do.
     */
    @Test
    fun toAndCcShareDeliveryZeroAndEachBccGetsItsOwn() = runBlocking {
        val addresses = listOf("alice@example.invalid", "carol@example.invalid", "dave@example.invalid", "erin@example.invalid")
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(addresses, TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(
            draft(to = "alice@example.invalid", cc = "carol@example.invalid", bcc = "dave@example.invalid, erin@example.invalid"),
            sign = false,
        )

        assertTrue("expected Sent, got $result", result is ClientSendOutcome.Sent)
        val message = transport.sent.single()
        assertEquals(3, message.deliveries.size)
        assertEquals(
            listOf("alice@example.invalid", "carol@example.invalid"),
            message.deliveries[0].recipients,
        )
        assertEquals(listOf("dave@example.invalid"), message.deliveries[1].recipients)
        assertEquals(listOf("erin@example.invalid"), message.deliveries[2].recipients)
    }

    /** No delivery may name a BCC recipient in a header — the relay refuses a `Bcc` header outright,
     *  and a BCC address appearing in another delivery's headers defeats the split entirely. */
    @Test
    fun noDeliveryHeaderMentionsABccRecipient() = runBlocking {
        val addresses = listOf("alice@example.invalid", "dave@example.invalid")
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(resolvedAll(addresses, TestPgpPrivateKey.ARMORED_PUBLIC)),
            transport = transport,
        ).send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        transport.sent.single().deliveries.forEach { delivery ->
            val headers = delivery.ciphertext.substringBefore("\r\n\r\n")
            assertFalse("a BCC address must not appear in any delivery header", headers.contains("dave@example.invalid"))
            assertFalse("no Bcc header at all", headers.lineSequence().any { it.startsWith("Bcc:") })
        }
    }

    /**
     * A BCC recipient's delivery is encrypted to their key alone.
     *
     * Asserted by decryption, not by inspecting recipient lists: the delivery must open with the BCC
     * recipient's key and must NOT open with the To recipient's, which is the property that actually
     * keeps the two apart.
     */
    @Test
    fun aBccDeliveryIsEncryptedOnlyToThatBccKey() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val resolver = FakeRecipientKeyResolver(
            ResolveResult.Success(
                listOf(
                    ResolvedRecipientKey("alice@example.invalid", TestPgpPrivateKey.ARMORED_PUBLIC, "", "contact-verified", true),
                    ResolvedRecipientKey("dave@example.invalid", TestPgpSecondKey.ARMORED_PUBLIC, "", "contact-verified", true),
                ),
            ),
        )
        sender(resolver = resolver, transport = transport)
            .send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        val bccDelivery = armorOf(transport.sent.single().deliveries[1].ciphertext)

        assertTrue(
            "the BCC recipient must be able to open their own delivery",
            PgpDecryptor.decrypt(TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(), bccDelivery, emptyList()) is DecryptResult.Ok,
        )
        assertTrue(
            "the To recipient must NOT be able to open the BCC delivery",
            PgpDecryptor.decrypt(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), bccDelivery, emptyList()) is DecryptResult.Failed,
        )
    }

    /** Key resolution happens before the biometric sheet, so a send that was going to be refused
     *  anyway never interrupts the user to authenticate for it. */
    @Test
    fun resolveRunsBeforeTheBiometricPrompt() = runBlocking {
        val opener = FakeVaultOpener()
        val result = sender(
            opener = opener,
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(ResolvedRecipientKey("alice@example.invalid", "", "", "none", false)),
                ),
            ),
        ).send(draft(), sign = false)

        assertTrue("expected KeysMissing, got $result", result is ClientSendOutcome.KeysMissing)
        assertEquals("the vault must not have been opened", 0, opener.opened)
    }

    @Test
    fun refusesWhenARecipientHasNoUsableKeyAndSendsNothing() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(
                        ResolvedRecipientKey("alice@example.invalid", TestPgpPrivateKey.ARMORED_PUBLIC, "", "contact-verified", true),
                        ResolvedRecipientKey("bob@example.invalid", "", "", "none", false),
                    ),
                ),
            ),
            transport = transport,
        ).send(draft(to = "alice@example.invalid, bob@example.invalid"), sign = false)

        assertEquals(listOf("bob@example.invalid"), (result as ClientSendOutcome.KeysMissing).addresses)
        assertTrue("nothing may be delivered", transport.sent.isEmpty())
    }

    /**
     * A broken TOFU pin is not a missing key and must not be reported as one.
     *
     * `key_changed` means discovery found a key whose fingerprint does not match the pinned one —
     * which is what a key rotation looks like, and also what an interception attempt looks like.
     * Folding it into "no key on file" tells the user nothing changed at the exact moment the one
     * thing worth telling them did.
     */
    @Test
    fun aChangedKeyOutranksAMissingKey() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                ResolveResult.Success(
                    listOf(
                        ResolvedRecipientKey("alice@example.invalid", "", "", "key_changed", false),
                        ResolvedRecipientKey("bob@example.invalid", "", "", "none", false),
                    ),
                ),
            ),
        ).send(draft(to = "alice@example.invalid, bob@example.invalid"), sign = false)

        assertEquals(listOf("alice@example.invalid"), (result as ClientSendOutcome.KeyChanged).addresses)
    }

    @Test
    fun cancelledUnlockSendsNothing() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        val result = sender(
            opener = FakeVaultOpener(outcome = OpenOutcome.Cancelled),
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        assertTrue("expected Cancelled, got $result", result is ClientSendOutcome.Cancelled)
        assertTrue(transport.sent.isEmpty())
    }

    @Test
    fun notClientProtectedIsPassedThrough() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(ResolveResult.NotClientProtected),
        ).send(draft(), sign = false)

        assertTrue("expected NotClientProtected, got $result", result is ClientSendOutcome.NotClientProtected)
    }

    /** No mail account configured, so no valid `From` can be built. Refuse locally rather than
     *  build ciphertext the relay will 403. */
    @Test
    fun blankAccountAddressRefusesBeforeResolving() = runBlocking {
        val resolver = FakeRecipientKeyResolver()
        val result = sender(resolver = resolver, accountAddress = "  ").send(draft(), sign = false)

        assertTrue("expected NoAccountAddress, got $result", result is ClientSendOutcome.NoAccountAddress)
        assertEquals("must not even resolve", 0, resolver.calls)
    }

    @Test
    fun everyDeliveryCarriesTheAccountAddressAsFrom() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid", "dave@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(to = "alice@example.invalid", bcc = "dave@example.invalid"), sign = false)

        val message = transport.sent.single()
        assertEquals(ACCOUNT, message.from)
        message.deliveries.forEach {
            assertTrue(
                "every delivery's From must equal the authorized account address",
                it.ciphertext.lineSequence().any { line -> line == "From: $ACCOUNT" },
            )
        }
    }

    /**
     * The Sent copy is encrypted to the public half of the **vault** key, never to anything the
     * server supplied.
     *
     * A hostile or compromised server that could hand back "your" public key would otherwise get a
     * readable copy of every message sent, with nothing on screen looking any different. Pinned by
     * decrypting with the vault key and proving the recipients' key cannot open it.
     */
    @Test
    fun theSentCopyIsEncryptedToTheVaultKeyNotAServerSuppliedOne() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            // Every recipient resolves to the SECOND key; the vault holds the first.
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpSecondKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        val sentCopy = armorOf(transport.sent.single().sentCopy)

        assertTrue(
            "the sender must be able to read their own Sent copy",
            PgpDecryptor.decrypt(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), sentCopy, emptyList()) is DecryptResult.Ok,
        )
        assertTrue(
            "a server-supplied recipient key must not be what the Sent copy was encrypted to",
            PgpDecryptor.decrypt(TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(), sentCopy, emptyList()) is DecryptResult.Failed,
        )
    }

    @Test
    fun signedSendProducesAVerifiableSignature() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = true)

        val decrypted = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            armorOf(transport.sent.single().deliveries[0].ciphertext),
            listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertTrue("the recipient must see a valid signature", decrypted.signature.valid)
    }

    /** The real subject reaches the recipient through the protected header, and never appears in
     *  the delivery's cleartext. */
    @Test
    fun theRecipientRecoversTheRealSubjectAndBody() = runBlocking {
        val transport = FakeClientEncryptedTransport()
        sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = transport,
        ).send(draft(), sign = false)

        val delivery = transport.sent.single().deliveries[0].ciphertext
        assertFalse("the real subject must not be in cleartext", delivery.contains("Subject: Subject"))

        val decrypted = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            armorOf(delivery),
            emptyList(),
        ) as DecryptResult.Ok
        val parsed = requireNotNull(PgpMimeReader.read(decrypted.plaintext))
        assertEquals("Subject", parsed.protectedSubject)
        assertEquals("<p>Body</p>", parsed.html?.trim())
    }

    @Test
    fun aTransportFailureIsReportedNotSwallowed() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = FakeClientEncryptedTransport(MailOutcome.UpstreamFailure("failed to send email")),
        ).send(draft(), sign = false)

        assertTrue("expected SendFailed, got $result", result is ClientSendOutcome.SendFailed)
    }

    @Test
    fun successCarriesTheServersWarning() = runBlocking {
        val result = sender(
            resolver = FakeRecipientKeyResolver(
                resolvedAll(listOf("alice@example.invalid"), TestPgpPrivateKey.ARMORED_PUBLIC),
            ),
            transport = FakeClientEncryptedTransport(
                MailOutcome.Success(MailSendOutcome(sentSaved = false, warning = "1 bcc delivery(s) failed")),
            ),
        ).send(draft(), sign = false)

        val sent = result as ClientSendOutcome.Sent
        assertEquals("1 bcc delivery(s) failed", sent.warning)
        assertFalse(sent.sentSaved)
    }
}
