package org.kysecurity.mail

import okhttp3.Call
import okhttp3.Request
import okhttp3.Response

/** [Result] failure is a thrown network exception; body decoding stays the caller's job. */
fun <T> Call.Factory.executeSync(request: Request, map: (Response) -> T): Result<T> = runCatching {
    newCall(request).execute().use(map)
}
