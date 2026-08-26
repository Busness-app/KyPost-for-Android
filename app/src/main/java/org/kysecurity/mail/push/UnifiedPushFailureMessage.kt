package org.kysecurity.mail.push

/** The sync error shown after UnifiedPush registration fails or is withdrawn.
 *
 *  It mentions a fallback only when this build has one. The message used to say
 *  "— reverted to Firebase" unconditionally, which on the F-Droid build is false in the worst
 *  direction: it tells a user whose notifications have just stopped that delivery was restored.
 *
 *  [canFallBack] is [ChannelPushTransport.canReplaceUnifiedPush], passed in rather than read here
 *  so both branches are reachable from a unit test — the flavor decides which one is real, and a
 *  test can only see one flavor at a time. */
fun unifiedPushFailureMessage(reason: String, canFallBack: Boolean): String =
    if (canFallBack) {
        "UnifiedPush registration failed: $reason — reverted to Firebase"
    } else {
        "UnifiedPush registration failed: $reason. Notifications are stopped until a " +
            "distributor is available again."
    }
