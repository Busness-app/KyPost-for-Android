package org.kysecurity.mail.push

import android.content.Context
import com.google.firebase.installations.FirebaseInstallations
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.tasks.await

/** Firebase Cloud Messaging, for the `play` and `github` channels.
 *
 *  Compiled only into those two — see the `src/gms/java` srcDir wiring in `app/build.gradle.kts`.
 *  The fdroid flavor gets `src/fdroid`'s implementation of the same name instead. */
object ChannelPush : ChannelPushTransport {

    /** No transport named, so the server derives `fcm` from `platform` exactly as it always has.
     *  Naming it here would be equally correct and would change the wire format for every
     *  existing install, for nothing. */
    override suspend fun registrationCredential(
        context: Context,
        store: PushStore,
    ): PushRegistrationCredential? =
        runCatching { FirebaseMessaging.getInstance().token.await() }
            .getOrNull()
            ?.let { PushRegistrationCredential(token = it) }

    override suspend fun tearDown(context: Context) {
        runCatching {
            FirebaseMessaging.getInstance().deleteToken().await()
            // Rotating the messaging token leaves the Firebase installation and its stable Fid in
            // place, which keeps the device linkable across an unpair and a later re-pair.
            FirebaseInstallations.getInstance().delete().await()
        }
    }

    /** Firebase is always available on these builds, so a UnifiedPush failure has somewhere to go. */
    override val canReplaceUnifiedPush: Boolean = true
}
