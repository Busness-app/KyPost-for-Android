package org.kysecurity.mail.mail

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// The $Phishing keyword is set by the server (backend/internal/processor/phish_scan.go).
class PhishingFlagTest {
    @Test
    fun recognizesTheServerKeyword() {
        assertTrue(isFlaggedPhishing(setOf("Primary", PHISHING_KEYWORD)))
    }

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
