package org.kysecurity.mail.push

import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The two transports used to decide this independently, and drifted: the Firebase service
 *  branched to the MFA screen and the UnifiedPush service never did, so a challenge delivered
 *  over UnifiedPush was parsed as mail, failed, and vanished. Routing lives in one place now,
 *  and these tests are what keeps it there. */
class IncomingPushRouterTest {

    private fun mfaChallenge() = mapOf(
        "type" to "mfa_challenge",
        "challengeId" to "c-1",
        "ipAddress" to "203.0.113.7",
        "userAgent" to "Firefox on Linux",
        "issuedAt" to "1750000000000",
        "matchDigits" to "42",
        "decoyDigits" to "17, 83",
    )

    private fun mail() = mapOf(
        "type" to "mail",
        "messageId" to "m-1",
        "sender" to "someone@example.test",
        "subject" to "Hello",
    )

    @Test
    fun route_sendsAnMfaChallengeToTheApprovalScreen() {
        val routed = IncomingPushRouter.route(mfaChallenge())

        assertTrue("expected Mfa, got $routed", routed is IncomingPush.Mfa)
        val challenge = (routed as IncomingPush.Mfa).payload
        assertTrue(challenge.challengeId == "c-1")
        assertTrue(challenge.matchDigits == "42")
    }

    @Test
    fun route_sendsMailToTheNotificationPath() {
        val routed = IncomingPushRouter.route(mail())

        assertTrue("expected Mail, got $routed", routed is IncomingPush.Mail)
    }

    /** An MFA challenge must never be shown as a mail notification. The sign-in context reads as a
     *  sender and subject, and the approve/deny buttons are simply absent — the user sees a
     *  message that does not exist and cannot act on the login. */
    @Test
    fun route_neverMistakesAnMfaChallengeForMail() {
        val routed = IncomingPushRouter.route(mfaChallenge())

        assertTrue(routed !is IncomingPush.Mail)
    }

    @Test
    fun route_returnsNullForSomethingItCannotIdentify() {
        assertNull(IncomingPushRouter.route(mapOf("type" to "not-a-thing")))
        assertNull(IncomingPushRouter.route(emptyMap()))
    }

    /** A challenge whose digits the server did not send cannot be approved, but it must still
     *  reach the approval screen: that screen is what tells the user a sign-in was attempted,
     *  which is the security-relevant half. Routing it to mail would hide the attempt. */
    @Test
    fun route_keepsAnUnapprovableChallengeOnTheMfaPath() {
        val routed = IncomingPushRouter.route(mfaChallenge() - "matchDigits")

        assertTrue("expected Mfa, got $routed", routed is IncomingPush.Mfa)
    }
}
