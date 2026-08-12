package org.kysecurity.mail

import okhttp3.Call
import okhttp3.Request
import okhttp3.Response

/**
 * Runs [request] through this [Call.Factory] and applies [map] to the response inside the same
 * `use` block, so callers don't each write their own `runCatching { ... .execute().use { } }`.
 * The [Result] failure branch is a thrown network exception; body decoding stays the caller's job.
 */
fun <T> Call.Factory.executeSync(request: Request, map: (Response) -> T): Result<T> = runCatching {
    newCall(request).execute().use(map)
}
