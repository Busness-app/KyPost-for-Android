package com.urlxl.mail.push

/**
 * An MFA challenge as pushed by the server.
 *
 * Everything past [challengeId] is *context for the human*, and it is the point of this screen.
 * The payload used to be the id alone, so [MfaApprovalActivity] — which its own KDoc calls "the
 * single highest-value action in this app" — asked the user to approve a sign-in with no origin,
 * no time, and no way to tell their own login from an attacker's. Every anti-fatigue control
 * around it (the five-minute window, per-challenge re-auth, the removal of notification actions,
 * the alert cooldown) guarded a decision the user had no information to make, which is precisely
 * the gap MFA-fatigue attacks walk through.
 *
 * All context fields are optional so a server that has not been updated yet still works; the UI
 * degrades to naming what it does not know rather than pretending there was nothing to show.
 * [matchDigits] additionally drives number matching — see [MfaApprovalActivity].
 */
data class MfaChallengePayload(
    val challengeId: String,
    val ipAddress: String = "",
    val approxLocation: String = "",
    val userAgent: String = "",
    val issuedAtEpochMs: Long = 0L,
    /** The digits the server is simultaneously showing in the browser that started the sign-in.
     *  Blank when the server does not support number matching. */
    val matchDigits: String = "",
    /** Decoy values the approval screen offers alongside [matchDigits]. Empty means the client
     *  generates its own. */
    val decoyDigits: List<String> = emptyList(),
)

object MfaChallengePayloadParser {
    private const val TYPE_MFA_CHALLENGE = "mfa_challenge"

    /** Context strings land in a TextView on a security-critical screen; an unbounded
     *  server-supplied string could push the approve/deny buttons off-screen. */
    private const val MAX_CONTEXT_LENGTH = 120

    const val MATCH_DIGITS_LENGTH = 2

    fun parse(data: Map<String, String>): MfaChallengePayload? =
        build(
            type = data["type"],
            challengeId = data["challengeId"],
            ipAddress = data["ipAddress"],
            approxLocation = data["approxLocation"],
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
            approxLocation = bundle.getString("approxLocation"),
            userAgent = bundle.getString("userAgent"),
            issuedAt = bundle.getString("issuedAt"),
            matchDigits = bundle.getString("matchDigits"),
            decoyDigits = bundle.getString("decoyDigits"),
        )

    private fun build(
        type: String?,
        challengeId: String?,
        ipAddress: String?,
        approxLocation: String?,
        userAgent: String?,
        issuedAt: String?,
        matchDigits: String?,
        decoyDigits: String?,
    ): MfaChallengePayload? {
        if (type != TYPE_MFA_CHALLENGE) return null
        val id = challengeId.orEmpty().trim()
        if (id.isBlank()) return null
        return MfaChallengePayload(
            challengeId = id,
            ipAddress = ipAddress.orEmpty().trim().take(MAX_CONTEXT_LENGTH),
            approxLocation = approxLocation.orEmpty().trim().take(MAX_CONTEXT_LENGTH),
            userAgent = userAgent.orEmpty().trim().take(MAX_CONTEXT_LENGTH),
            issuedAtEpochMs = issuedAt?.trim()?.toLongOrNull()?.takeIf { it > 0L } ?: 0L,
            // Only well-formed digit runs: these drive tap targets, so neither the server nor
            // anyone who can reach the push channel gets to put arbitrary text on a button.
            matchDigits = matchDigits.orEmpty().trim().takeIf { it.isValidMatchDigits() }.orEmpty(),
            decoyDigits = decoyDigits.orEmpty().split(',')
                .map { it.trim() }
                .filter { it.isValidMatchDigits() }
                .distinct(),
        )
    }

    private fun String.isValidMatchDigits(): Boolean =
        length == MATCH_DIGITS_LENGTH && all { it.isDigit() }
}
