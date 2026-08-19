package org.kysecurity.mail.mail

// Reserved RFC 8621 keyword, mirrored in the TS and QML clients — the literal is the contract.
const val PHISHING_KEYWORD = "\$Phishing"

fun isFlaggedPhishing(keywords: Set<String>): Boolean =
    keywords.any { it.trim().equals(PHISHING_KEYWORD, ignoreCase = true) }
