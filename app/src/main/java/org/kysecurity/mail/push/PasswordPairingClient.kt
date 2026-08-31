package org.kysecurity.mail.push

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.kysecurity.mail.executeSync

@Serializable
private data class PasswordPairingRequest(
    @SerialName("username") val username: String,
    @SerialName("password") val password: String,
) {
    override fun toString(): String = "PasswordPairingRequest(redacted)"
}

@Serializable
private data class PasswordPairingResponse(@SerialName("deepLink") val deepLink: String = "")

class PasswordPairingClient(
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    suspend fun mint(serverUrl: String, username: String, password: String): PairingParseResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/notifications/review-pairing")
            ?: return PairingParseResult.Error("Server URL must use https")
        if (username.isBlank() || password.isBlank()) return PairingParseResult.Error("Enter your username and password")
        val body = json.encodeToString(PasswordPairingRequest(username.trim(), password))
        val request = Request.Builder()
            .url(endpoint)
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, raw) = result.getOrNull()
            ?: return PairingParseResult.Error(result.exceptionOrNull()?.message ?: "Could not reach the server")
        if (code != 200) {
            val message = when (code) {
                401 -> "Username or password is incorrect"
                403 -> "This account requires an interactive sign-in"
                404 -> "Fast pairing is not enabled on this server"
                429 -> "Too many attempts. Try again later"
                else -> "Could not pair with the server ($code)"
            }
            return PairingParseResult.Error(message)
        }
        val deepLink = runCatching { json.decodeFromString<PasswordPairingResponse>(raw).deepLink }.getOrNull().orEmpty()
        return NativePairingDeepLinkParser.parse(deepLink)
    }
}
