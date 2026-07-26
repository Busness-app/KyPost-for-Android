package com.urlxl.mail.push

import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

@Serializable
data class PairingData(
    val subscriberId: String,
    val serverUrl: String,
    val registrationUrl: String,
    val pairingToken: String,
    val deviceId: String?,
    val deviceSecret: String?,
    val pairedAtEpochMs: Long,
)

/**
 * True when [candidate] and [reference] are the same https origin (scheme + host + effective port).
 *
 * Every URL this app will send pairing credentials to has to pass this. The registration endpoint
 * mints and returns the device secret, so a QR that names one server in the `srv` parameter — the
 * one the confirmation dialog shows the user — and a different one in `reg` would POST the
 * subscriber ID, pairing token and FCM token to an attacker while displaying a trusted hostname.
 * The pull endpoint already had this check; the endpoint that carries the credential did not.
 */
internal fun sameOrigin(candidate: String, reference: String): Boolean {
    val a = runCatching { URI(candidate) }.getOrNull() ?: return false
    val b = runCatching { URI(reference) }.getOrNull() ?: return false
    if (a.host.isNullOrBlank() || b.host.isNullOrBlank()) return false
    return a.scheme.equals(b.scheme, ignoreCase = true) &&
        a.host.equals(b.host, ignoreCase = true) &&
        effectivePort(a) == effectivePort(b)
}

private fun effectivePort(uri: URI): Int =
    if (uri.port != -1) uri.port else if (uri.scheme.equals("https", ignoreCase = true)) 443 else 80

object NativeRegistrationEndpointResolver {
    sealed class Resolution {
        data class Resolved(val registrationUrl: String) : Resolution()
        object MissingServerUrl : Resolution()
    }

    /**
     * A server-supplied [qrReg] wins only if it is the same origin as [qrServerUrl]; anything else
     * falls back to the endpoint derived from the paired server. Mirrors [resolvePullEndpoint], and
     * is the second gate behind [NativePairingDeepLinkParser], which rejects a cross-origin `reg`
     * outright — this one also covers a pairing persisted by an older build.
     */
    fun resolve(qrReg: String?, qrServerUrl: String?): Resolution {
        val srv = qrServerUrl?.takeIf { it.isNotBlank() }?.trimEnd('/')
        val reg = qrReg?.takeIf { it.isNotBlank() }

        if (srv == null) {
            // With no server URL there is nothing to validate a reg URL against, so it cannot be
            // trusted either — this is an unusable pairing, not a reg-only one.
            return Resolution.MissingServerUrl
        }
        if (reg != null && sameOrigin(reg, srv)) return Resolution.Resolved(reg)
        return Resolution.Resolved("$srv/api/notifications/native/register")
    }
}

sealed class PairingParseResult {
    data class Success(val pairing: PairingData) : PairingParseResult()
    data class Error(val reason: String) : PairingParseResult()
}

object NativePairingDeepLinkParser {
    fun parse(link: String, nowEpochMs: Long = System.currentTimeMillis()): PairingParseResult {
        val uri = runCatching { URI(link.trim()) }.getOrNull()
            ?: return PairingParseResult.Error("Invalid deep link")

        if (!uri.scheme.equals("kypost", ignoreCase = true) ||
            !uri.host.equals("native-pair", ignoreCase = true)
        ) {
            return PairingParseResult.Error("Unsupported deep link")
        }

        val query = parseQuery(uri.rawQuery.orEmpty())

        val sub = query["sub"].orEmpty().trim()
        val srv = query["srv"].orEmpty().trim()
        val reg = query["reg"].orEmpty().trim().takeIf { it.isNotBlank() }
        val pt = query["pt"].orEmpty().trim()

        if (sub.isBlank()) return PairingParseResult.Error("Missing sub parameter")
        if (pt.isBlank()) return PairingParseResult.Error("Missing pairing token")
        if (srv.isBlank()) return PairingParseResult.Error("Missing server URL")
        // The server is arbitrary (self-hosted relays, no fixed domain to allowlist), so https-only
        // is the one property we can enforce — it stops a plain-http deep link/QR from pointing the
        // device's pairing token and subscriber credentials at an unencrypted, spoofable endpoint.
        if (!isHttpsUrl(srv)) {
            return PairingParseResult.Error("Server URL must use https")
        }
        if (reg != null && !isHttpsUrl(reg)) {
            return PairingParseResult.Error("Registration URL must use https")
        }
        // https alone is not enough: https://evil.example is a perfectly valid https URL. The
        // registration URL is where the device secret is minted, and the confirmation dialog shows
        // the user srv — so reg has to be the same server, or the dialog is lying about where the
        // credentials are going. See [sameOrigin].
        if (reg != null && !sameOrigin(reg, srv)) {
            return PairingParseResult.Error("Registration URL must be on the same server as the server URL")
        }

        return PairingParseResult.Success(
            PairingData(
                subscriberId = sub,
                serverUrl = srv,
                registrationUrl = reg.orEmpty(),
                pairingToken = pt,
                deviceId = null,
                deviceSecret = null,
                pairedAtEpochMs = nowEpochMs,
            ),
        )
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        return rawQuery.split('&')
            .mapNotNull { part ->
                val index = part.indexOf('=')
                if (index < 0) return@mapNotNull null
                val key = decode(part.substring(0, index))
                val value = decode(part.substring(index + 1))
                key to value
            }
            .toMap()
    }

    private fun decode(value: String): String {
        return URLDecoder.decode(value, StandardCharsets.UTF_8.name())
    }

    private fun isHttpsUrl(value: String): Boolean {
        val parsed = runCatching { URI(value) }.getOrNull() ?: return false
        return parsed.scheme.equals("https", ignoreCase = true) && !parsed.host.isNullOrBlank()
    }
}
