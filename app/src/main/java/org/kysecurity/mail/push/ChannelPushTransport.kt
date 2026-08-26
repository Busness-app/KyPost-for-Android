package org.kysecurity.mail.push

import android.content.Context

/** The push transport a distribution channel ships with.
 *
 *  `play` and `github` carry Firebase. `fdroid` carries none, because F-Droid refuses proprietary
 *  dependencies — a flavor that merely disables FCM at runtime still ships the library and is
 *  still refused. Exactly one `ChannelPush` is on the compile path per flavor: `src/gms`, shared
 *  by play and github, or `src/fdroid`.
 *
 *  Everything that names `com.google.*` lives behind this interface. Nothing in `src/main` may
 *  import it, which is what makes the fdroid APK verifiably Google-free rather than
 *  Google-free-by-inspection. */
interface ChannelPushTransport {

    /** The credential to register with, or null when this build cannot produce one right now.
     *
     *  Null is not an error state to paper over: on a Firebase build it means Firebase could not
     *  mint a token, and on a Firebase-free one it usually means no UnifiedPush distributor is
     *  installed. Either way registering without it produces a device the server believes it can
     *  reach and cannot. */
    suspend fun registrationCredential(context: Context, store: PushStore): PushRegistrationCredential?

    /** Severs this transport's own delivery state, after the transport-neutral teardown has run.
     *  Called on unpair and on wipe. */
    suspend fun tearDown(context: Context)

    /** Whether a failed or abandoned UnifiedPush registration can revert to this transport.
     *
     *  False on a build with no second transport, where "reverting to Firebase" would leave the
     *  device paired, registered, and permanently silent — which is worse than reporting the
     *  failure, because nothing about it is visible until mail stops arriving. */
    val canReplaceUnifiedPush: Boolean
}
