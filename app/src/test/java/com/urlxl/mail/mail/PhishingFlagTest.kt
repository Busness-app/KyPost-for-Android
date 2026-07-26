package com.urlxl.mail.mail

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The $Phishing IMAP keyword is how the server tells this client a message
// impersonates KyPost (backend/internal/processor/phish_scan.go). The warning
// bar in EmailDetailActivity reads it through this predicate.
//
// Advisory only: the links it warns about are already refused by
// SAFE_LINK_SCHEMES, whether or not the server ever flagged the message.
class PhishingFlagTest {
    @Test
    fun recognizesTheServerKeyword() {
        assertTrue(isFlaggedPhishing(setOf("Primary", PHISHING_KEYWORD)))
    }

    // IMAP keywords are case-insensitive, so a server may echo back a different
    // case than the one the poller set. A case-sensitive check would silently
    // drop the warning on exactly the mail it exists for.
    @Test
    fun matchingIsCaseInsensitive() {
        assertTrue(isFlaggedPhishing(setOf("\$phishing")))
        assertTrue(isFlaggedPhishing(setOf("\$PHISHING")))
        assertTrue(isFlaggedPhishing(setOf("\$PhIsHiNg")))
    }

    @Test
    fun surroundingWhitespaceIsTolerated() {
        assertTrue(isFlaggedPhishing(setOf("  \$Phishing  ")))
    }

    @Test
    fun ordinaryMailIsNotFlagged() {
        assertFalse(isFlaggedPhishing(setOf("Primary", "Receipts")))
    }

    @Test
    fun partialMatchesDoNotCount() {
        assertFalse(isFlaggedPhishing(setOf("\$PhishingReport")))
        assertFalse(isFlaggedPhishing(setOf("NotPhishing")))
    }

    @Test
    fun emptyKeywordsAreNotFlagged() {
        assertFalse(isFlaggedPhishing(emptySet()))
    }
}
