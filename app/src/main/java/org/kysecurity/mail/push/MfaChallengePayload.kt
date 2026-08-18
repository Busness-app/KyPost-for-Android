package org.kysecurity.mail.push

/**
 * An MFA challenge as pushed by the server.
 *
 * All context fields are optional so a server that has not been updated yet still works; the UI
 * degrades to naming what it does not know rather than pretending there was nothing to show.
 * [matchDigits] additionally drives number matching — see [MfaApprovalActivity].
 */
data class MfaChallengePayload(
    val challengeId: String,
    val ipAddress: String = "",
    val userAgent: String = "",
    val issuedAtEpochMs: Long = 0L,
    /** The digits the server is simultaneously showing in the browser that started the sign-in.
     *  Blank when the server sent nothing usable, in which case this challenge cannot be approved
     *  — see [MfaNumberMatch]. */
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

    /**
     * Bound on the challenge id itself, which is the field that matters most and was the only one
     * with no bound at all.
     *
     * Every *display* string above is length-capped and the number-match values are shape-checked,
     * but the id becomes a **key in a `SharedPreferences` XML file** ([MfaChallengeTracker]), written
     * with a synchronous `commit()` on the push-delivery thread, and `prefs.all` is materialised on
     * every subsequent delivery. A hostile relay sending megabytes here filled the disk and stalled
     * the delivery thread through an input path that was already being validated for the fields that
     * only ever reach a TextView.
     *
     * The charset is restricted for the same reason: this is a server-minted opaque id (UUID-shaped
     * in practice), never free text, and it is used as a filename-adjacent map key.
     */
    private const val MAX_CHALLENGE_ID_LENGTH = 128
    private val CHALLENGE_ID_CHARS = Regex("^[A-Za-z0-9._:-]+$")

    /**
     * Accepted width of a number-match value, as a range rather than a constant.
     */
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
