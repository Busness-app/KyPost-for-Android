package org.kysecurity.mail.push

/** An MFA challenge as pushed by the server; context fields are optional for older servers. */
data class MfaChallengePayload(
    val challengeId: String,
    val ipAddress: String = "",
    val userAgent: String = "",
    val issuedAtEpochMs: Long = 0L,
    /** Blank when the server sent nothing usable — this challenge cannot be approved. */
    val matchDigits: String = "",
    /** The wrong values the approval screen offers alongside [matchDigits]. The server mints these;
     *  the client never invents them. */
    val decoyDigits: List<String> = emptyList(),
)

object MfaChallengePayloadParser {
    private const val TYPE_MFA_CHALLENGE = "mfa_challenge"

    /** Context strings land in a TextView on a security-critical screen; an unbounded
     *  server-supplied string could push the approve/deny buttons off-screen. */
    private const val MAX_CONTEXT_LENGTH = 120

    /** The id becomes a SharedPreferences key written on the delivery thread, hence bounded. */
    private const val MAX_CHALLENGE_ID_LENGTH = 128
    private val CHALLENGE_ID_CHARS = Regex("^[A-Za-z0-9._:-]+$")

    const val MATCH_DIGITS_MIN_LENGTH = 1
    const val MATCH_DIGITS_MAX_LENGTH = 6

    fun parse(data: Map<String, String>): MfaChallengePayload? =
        build(
            type = data["type"],
            challengeId = data["challengeId"],
            ipAddress = data["ipAddress"],
            userAgent = data["userAgent"],
            issuedAt = data["issuedAt"],
            matchDigits = data["matchDigits"],
            decoyDigits = data["decoyDigits"],
        )

    fun parse(bundle: android.os.Bundle): MfaChallengePayload? =
        build(
            type = bundle.getString("type"),
            challengeId = bundle.getString("challengeId"),
            ipAddress = bundle.getString("ipAddress"),
            userAgent = bundle.getString("userAgent"),
            issuedAt = bundle.getString("issuedAt"),
            matchDigits = bundle.getString("matchDigits"),
            decoyDigits = bundle.getString("decoyDigits"),
        )

    private fun build(
        type: String?,
        challengeId: String?,
        ipAddress: String?,
        userAgent: String?,
        issuedAt: String?,
        matchDigits: String?,
        decoyDigits: String?,
    ): MfaChallengePayload? {
        if (type != TYPE_MFA_CHALLENGE) return null
        val id = challengeId.orEmpty().trim()
        if (!isValidChallengeId(id)) return null
        return MfaChallengePayload(
            challengeId = id,
            ipAddress = ipAddress.orEmpty().trim().take(MAX_CONTEXT_LENGTH),
            userAgent = userAgent.orEmpty().trim().take(MAX_CONTEXT_LENGTH),
            issuedAtEpochMs = issuedAt?.trim()?.toLongOrNull()?.takeIf { it > 0L } ?: 0L,
            // Only well-formed digit runs: these drive tap targets, so neither the server nor
            // anyone who can reach the push channel gets to put arbitrary text on a button.
            matchDigits = matchDigits.orEmpty().trim().takeIf { isValidMatchDigits(it) }.orEmpty(),
            decoyDigits = decoyDigits.orEmpty().split(',')
                .map { it.trim() }
                .filter { isValidMatchDigits(it) }
                .distinct(),
        )
    }

    /** Shape only. Whether a *set* of these adds up to an approvable challenge is
     *  [MfaNumberMatch.optionsFor]'s decision. */
    fun isValidMatchDigits(value: String): Boolean =
        value.length in MATCH_DIGITS_MIN_LENGTH..MATCH_DIGITS_MAX_LENGTH && value.all { it.isDigit() }

    /** See [MAX_CHALLENGE_ID_LENGTH]. Public so [MfaChallengeTracker] can refuse to persist an id
     *  that did not come through this parser, rather than trusting its callers to have checked. */
    fun isValidChallengeId(value: String): Boolean =
        value.length in 1..MAX_CHALLENGE_ID_LENGTH && CHALLENGE_ID_CHARS.matches(value)
}
