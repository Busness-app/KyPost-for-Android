package org.kysecurity.mail

object KeywordTabs {
    const val ALL = "All"

    fun buildTabs(emails: List<Email>): List<String> {
        val keywords = emails
            .flatMap { it.keywords }
            .filter { it.isNotBlank() }
            .distinct()
            .sortedBy { it.lowercase() }
        return listOf(ALL) + keywords
    }

    fun filterEmails(emails: List<Email>, selectedTab: String): List<Email> {
        if (selectedTab == ALL) {
            return emails
        }
        return emails.filter { it.keywords.contains(selectedTab) }
    }
}

