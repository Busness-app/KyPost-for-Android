package org.kysecurity.mail.push

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.kysecurity.mail.MainActivity
import org.kysecurity.mail.R

object PushNotificationDispatcher : org.kysecurity.mail.ProcessScopedState {
    private const val CHANNEL_ID = "kypost_push"
    private const val MFA_CHANNEL_ID = "kypost_mfa"
    private const val MFA_GROUP_KEY = "org.kysecurity.mail.push.MFA"

    /**
     * Repeat MFA challenges inside this window post silently instead of alerting again — the
     * client-side half of MFA-fatigue resistance (the server caps push rate; see mfaPushLimiter).
     */
    private const val MFA_ALERT_COOLDOWN_MS = 30 * 1000L

    /**
     * Live challenges past which individual notifications stop being posted.
     *
     * Silencing the *sound* is not flood control: every challenge still got its own notification id
     * and its own row in the shade, so a relay minting thousands of challenges buried the device in
     * exactly the feature built to resist that. Past this threshold the challenges collapse into
     * one summary on a fixed id, which says plainly that something is wrong.
     */
    private const val MFA_BURST_THRESHOLD = 3

    /** Fixed id, so a burst overwrites one row instead of accumulating. */
    private val MFA_BURST_NOTIFICATION_ID = stableNotificationId("mfa-burst")

    /**
     * The notification id each challenge was actually posted under.
     *
     * Bounded by the same ceiling as the tracker: entries are removed on cancel, but a challenge
     * that is never answered would otherwise linger for the life of the process.
     */
    private val postedNotificationIds = object : LinkedHashMap<String, Int>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Int>): Boolean = size > MAX_TRACKED_CHALLENGES
    }

    /**
     * The challenge the burst summary currently points at, or null when no burst row is showing.
     */
    @Volatile
    private var burstChallengeId: String? = null

    init {
        // Both fields above are account-scoped bookkeeping in a process that AppRestart no longer
        // kills: a stale burst pointer or a stale posted-id map outlives an unpair and then makes
        // the next session cancel the wrong notification. See [org.kysecurity.mail.ProcessScopedState].
        org.kysecurity.mail.ProcessState.register(this)
    }

    override fun resetForNewSession() {
        synchronized(postedNotificationIds) {
            postedNotificationIds.clear()
            burstChallengeId = null
        }
    }

    const val EXTRA_MFA_CHALLENGE_ID = "challengeId"
    const val EXTRA_MFA_IP = "mfaIpAddress"
    const val EXTRA_MFA_USER_AGENT = "mfaUserAgent"
    const val EXTRA_MFA_ISSUED_AT = "mfaIssuedAt"
    const val EXTRA_MFA_MATCH_DIGITS = "mfaMatchDigits"
    const val EXTRA_MFA_DECOY_DIGITS = "mfaDecoyDigits"
    const val EXTRA_MESSAGE_ID = "org.kysecurity.mail.push.EXTRA_MESSAGE_ID"
    const val EXTRA_SENDER = "org.kysecurity.mail.push.EXTRA_SENDER"
    const val EXTRA_SUBJECT = "org.kysecurity.mail.push.EXTRA_SUBJECT"

    /**
     * Channel ids this app posted to before the KyPost rename.
     *
     * A [NotificationChannel] outlives the constant that created it: the system keeps one until it
     * is explicitly deleted or the app is uninstalled. So renaming `CHANNEL_ID`/`MFA_CHANNEL_ID`
     * created the new pair and left the old pair registered — a user opening this app's Android
     * notification settings to decide what it may interrupt them for is shown four channels, two of
     * them Llama-branded, and the toggles on those two govern nothing because nothing posts to them.
     */
    private val LEGACY_CHANNEL_IDS = listOf("llama_labels_push", "llama_labels_mfa")

    /** [pruneLegacyChannels] runs once per process — see its doc. */
    private val legacyChannelsPruned = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Deletes [LEGACY_CHANNEL_IDS].
     *
     * Needs no persisted "already done" flag: deleting a channel that is not there is a no-op, so
     * repeating it is only ever wasted work, never wrong. It is still guarded to once per process,
     * because both callers run on push-delivery threads and this is a binder call per id — the same
     * reason those callers already return early when their own channel exists.
     */
    private fun pruneLegacyChannels(manager: NotificationManager) {
        if (!legacyChannelsPruned.compareAndSet(false, true)) return
        LEGACY_CHANNEL_IDS.forEach { manager.deleteNotificationChannel(it) }
    }

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        pruneLegacyChannels(manager)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "KyPost",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Push notifications for labeled email events"
        }
        manager.createNotificationChannel(channel)
    }

    fun ensureMfaChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        pruneLegacyChannels(manager)
        if (manager.getNotificationChannel(MFA_CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            MFA_CHANNEL_ID,
            "Sign-in approvals",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Approve or deny sign-in attempts to your account"
        }
        manager.createNotificationChannel(channel)
    }

    /**
     * Posts a new-mail notification, with lock-screen redaction delegated to the framework.
     *
     * [NotificationCompat.Builder.setPublicVersion] is the framework's mechanism for exactly this
     * decision, and it is a better one on both sides. The system swaps the two forms live off
     * *keyguard* state, so the redacted form shows while the phone is locked (which is the threat
     * the old branch was reaching for — app-lock state was only ever a proxy for it) and the real
     * sender and subject appear in the shade once it is not.
     *
     * "Require Unlock to Open" is enforced where it was always actually enforced, on the tap target:
     * [MainActivity] extends [org.kysecurity.mail.security.LockedActivity], which finishes it and shows
     * the unlock screen.
     */
    fun show(context: Context, payload: PushPayload) {
        ensureChannel(context)
        if (!notificationsAllowed(context)) return

        // Post the redacted form as the *whole* notification, not just its public version: with the
        // credential gate on, the user has explicitly accepted losing notification content until
        // they unlock the app, and the framework's public/private swap keys off the keyguard, which
        // says nothing about this app's own lock. Unlike the branch this replaces, the row is
        // re-posted with real content by the next delivery after unlocking, and the id is stable so
        // it updates in place rather than stacking.
        if (contentSuppressedWhileLocked(context)) {
            postNotification(
                context,
                uniqueNotificationId("mail-${payload.messageId}"),
                redactedNotification(context, payload),
            )
            return
        }

        val notificationId = uniqueNotificationId("mail-${payload.messageId}")
        val pendingIntent = mailPendingIntent(context, payload, notificationId)

        val body = PushPayloadParser.body(payload)

        val redacted = redactedNotification(context, payload)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(PushPayloadParser.title(payload))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            // PRIVATE, not SECRET: SECRET suppresses the row on the lock screen outright, which
            // also suppresses the public version there and leaves nothing to swap in.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(redacted)
            .setContentIntent(pendingIntent)
            .build()

        postNotification(context, notificationId, notification)
    }

    /** The tap target for a mail notification. Both forms of the row carry the same one — the
     *  unlock gate is on the Activity, not on which form was tapped. */
    private fun mailPendingIntent(context: Context, payload: PushPayload, notificationId: Int): PendingIntent {
        val launchIntent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_MESSAGE_ID, payload.messageId)
            .putExtra(EXTRA_SENDER, payload.senderName)
            .putExtra(EXTRA_SUBJECT, payload.emailSubject)
        return PendingIntent.getActivity(
            context,
            notificationId,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    /** That something arrived, and nothing about what. Used as the lock-screen public version
     *  always, and as the entire notification when [contentSuppressedWhileLocked]. */
    private fun redactedNotification(context: Context, payload: PushPayload): android.app.Notification {
        val notificationId = uniqueNotificationId("mail-${payload.messageId}")
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notification_hidden_while_locked))
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(mailPendingIntent(context, payload, notificationId))
            .build()
    }

    /**
     * True when the user turned on "Require unlock to receive push/MFA" and the app is currently
     * locked, so no message metadata may be shown until they enter their PIN.
     *
     * Reads [org.kysecurity.mail.security.AppLockManager.isLockedNow] rather than the `locked` flow, for
     * the same reason every other security decision does: a background grace window that has expired
     * without `lockNow()` having fired yet is still locked.
     *
     * Failing closed on an exception is deliberate. This runs on the delivery path in a process that
     * may have just started, and the alternative to "redact" is "print the sender and subject of a
     * message to the shade" — the wrong way to resolve a question about the user's security posture.
     */
    private fun contentSuppressedWhileLocked(context: Context): Boolean = runCatching {
        val graph = org.kysecurity.mail.security.SecurityRuntime.graph(context)
        graph.appLockStore.isCredentialPinGateEnabled() && graph.appLockManager.isLockedNow()
    }.getOrElse {
        android.util.Log.e("PushNotificationDispatcher", "Could not read the credential gate; redacting", it)
        true
    }

    /**
     * Posts the tap-to-review prompt for an MFA challenge.
     *
     * There are deliberately no "Approve"/"Deny" notification actions. Notification actions fire
     * from the lock screen without any authentication, so they let anyone holding the powered-on
     * device approve a sign-in to the account — bypassing the PIN, biometric, lockout and wipe
     * apparatus wholesale, and bypassing the [MfaChallengeTracker] check as well, since the
     * receiver they invoked never consulted it. The decision now only happens inside
     * [MfaApprovalActivity], behind re-authentication.
     */
    fun showMfaChallenge(context: Context, payload: MfaChallengePayload) {
        val tracker = PushRuntime.graph(context).mfaChallengeTracker
        val burst = tracker.liveCount() >= MFA_BURST_THRESHOLD
        val alert = tracker.shouldSuppressAlert(MFA_ALERT_COOLDOWN_MS)
        // Tracked (below) only once a notification for it is actually on screen. Marking first
        // meant that with POST_NOTIFICATIONS denied — or any SecurityException on the way out — the
        // challenge became answerable for five minutes with nothing ever shown to the user, which
        // is the pretext an approval screen must not be reachable under. The alert cooldown is
        // rolled back on the same failure and for the same reason: a delivery the user never saw
        // must not silence the next five minutes of real ones.
        val notificationId = postMfaNotification(context, payload, burst, alert.suppress)
            ?: return tracker.restoreAlertCooldown(alert.previousAlertAtEpochMs)

        synchronized(postedNotificationIds) {
            if (burst) {
                // The summary can only point at one challenge, and this call has just repointed it.
                // Revoke the one it used to point at, so "tracked" keeps meaning "reachable from a
                // notification the user was actually shown". Without this, a flood silently
                // accumulated answerable challenges behind a single row.
                burstChallengeId
                    ?.takeIf { it != payload.challengeId }
                    ?.let { superseded ->
                        tracker.clear(superseded)
                        postedNotificationIds.remove(superseded)
                    }
                burstChallengeId = payload.challengeId
            }
            postedNotificationIds[payload.challengeId] = notificationId
        }
        tracker.markDelivered(payload.challengeId)
    }

    /**
     * Puts a challenge's notification back after a failed approve/deny, without touching the
     * tracker.
     *
     * `setAutoCancel(true)` removed the row the moment the user tapped it, so a send that never
     * reached the server left them with a toast, an Activity they were about to leave, and no route
     * back to a challenge that is still open — for the rest of its five-minute window.
     * [MfaResponder] claimed in a comment to do this and did not.
     *
     * Deliberately does **not** call [MfaChallengeTracker.markDelivered]: the entry is still there
     * (only a *successful* response clears it) and re-marking would slide the freshness deadline
     * forward, extending an answerable window because the network failed. Silent, too — the user is
     * looking at the screen; this is a breadcrumb, not an alert.
     */
    fun repostMfaChallenge(context: Context, payload: MfaChallengePayload) {
        // Only what is still answerable. A wrong number-match burns the challenge (tracker entry
        // removed) *before* the deny is sent, precisely so the burn holds when the deny fails —
        // re-posting there would put back a row whose only effect on tap is an Activity that
        // finishes instantly.
        if (!PushRuntime.graph(context).mfaChallengeTracker.isPending(payload.challengeId)) return
        val burst = synchronized(postedNotificationIds) { burstChallengeId == payload.challengeId }
        postMfaNotification(context, payload, burst, silent = true)
    }

    /** Builds and posts the row, returning the id it went out under, or null if nothing was
     *  posted. Shared by [showMfaChallenge] and [repostMfaChallenge] so the two cannot drift in
     *  what they put on screen. */
    private fun postMfaNotification(
        context: Context,
        payload: MfaChallengePayload,
        burst: Boolean,
        silent: Boolean,
    ): Int? {
        ensureMfaChannel(context)
        val notificationId = if (burst) MFA_BURST_NOTIFICATION_ID else mfaNotificationId(payload.challengeId)
        val tapPendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            mfaApprovalIntent(context, payload),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, MFA_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(
                context.getString(
                    if (burst) R.string.mfa_notification_burst_title else R.string.mfa_notification_title,
                ),
            )
            .setContentText(
                context.getString(
                    if (burst) R.string.mfa_notification_burst_body else R.string.mfa_notification_body,
                ),
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setGroup(MFA_GROUP_KEY)
            .setSilent(silent)
            .setContentIntent(tapPendingIntent)
            .build()

        return if (postNotification(context, notificationId, notification)) notificationId else null
    }

    /**
     * Rebuilds the payload an [mfaApprovalIntent] was assembled from.
     *
     * Kept next to its inverse so the two cannot drift: [MfaApprovalActivity] needs the whole
     * payload (not just the id) to hand back to [MfaResponder] for [repostMfaChallenge], and
     * reading the seven extras out by hand at each use site is how they drift apart.
     */
    fun payloadFrom(intent: Intent): MfaChallengePayload? {
        val id = intent.getStringExtra(EXTRA_MFA_CHALLENGE_ID).orEmpty()
        if (!MfaChallengePayloadParser.isValidChallengeId(id)) return null
        return MfaChallengePayload(
            challengeId = id,
            ipAddress = intent.getStringExtra(EXTRA_MFA_IP).orEmpty(),
            userAgent = intent.getStringExtra(EXTRA_MFA_USER_AGENT).orEmpty(),
            issuedAtEpochMs = intent.getLongExtra(EXTRA_MFA_ISSUED_AT, 0L),
            matchDigits = intent.getStringExtra(EXTRA_MFA_MATCH_DIGITS).orEmpty(),
            decoyDigits = intent.getStringArrayExtra(EXTRA_MFA_DECOY_DIGITS)?.toList().orEmpty(),
        )
    }

    /**
     * The intent that opens [MfaApprovalActivity] for [payload] — the only way one is built, and
     * now the only route to that screen at all.
     *
     * Every field matters. A challenge that arrives without `matchDigits` and its decoys cannot be
     * approved (see [MfaNumberMatch]), so an entry point that assembled a partial intent would not
     * degrade the screen, it would disable it.
     *
     * The context is safe in Intent extras: [MfaApprovalActivity] is not exported, so only this app
     * can supply them, and [MfaChallengeTracker] still gates on the id having really been pushed.
     */
    private fun mfaApprovalIntent(context: Context, payload: MfaChallengePayload): Intent =
        Intent(context, MfaApprovalActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_MFA_CHALLENGE_ID, payload.challengeId)
            .putExtra(EXTRA_MFA_IP, payload.ipAddress)
            .putExtra(EXTRA_MFA_USER_AGENT, payload.userAgent)
            .putExtra(EXTRA_MFA_ISSUED_AT, payload.issuedAtEpochMs)
            .putExtra(EXTRA_MFA_MATCH_DIGITS, payload.matchDigits)
            .putExtra(EXTRA_MFA_DECOY_DIGITS, payload.decoyDigits.toTypedArray())

    /**
     * Single exit point for posting, so the POST_NOTIFICATIONS check and the failure handling live
     * in one place.
     *
     * [notificationsAllowed] is still the gate, but the permission can be revoked between that check
     * and this call, and both call sites run on FCM/UnifiedPush delivery threads where an uncaught
     * `SecurityException` takes out the message handler rather than merely dropping one notification.
     */
    private fun postNotification(context: Context, id: Int, notification: android.app.Notification): Boolean {
        if (!notificationsAllowed(context)) return false
        return try {
            NotificationManagerCompat.from(context).notify(id, notification)
            true
        } catch (e: SecurityException) {
            android.util.Log.w("PushNotifications", "POST_NOTIFICATIONS revoked; dropping notification", e)
            false
        }
    }

    /**
     * Cancels the notification this challenge was posted under — [postedNotificationIds], not a
     * recomputed per-challenge id, because during a burst it was posted under the shared summary id.
     *
     * Falls back to the derived id when nothing is recorded, which covers the process having been
     * restarted between the notification being posted and the user answering it. FCM routinely does
     * exactly that, and outside a burst the derived id is correct.
     */
    fun cancelMfaChallenge(context: Context, challengeId: String) {
        val notificationId = synchronized(postedNotificationIds) {
            if (burstChallengeId == challengeId) burstChallengeId = null
            postedNotificationIds.remove(challengeId)
        } ?: mfaNotificationId(challengeId)
        NotificationManagerCompat.from(context).cancel(notificationId)
    }

    private fun notificationsAllowed(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }

    internal fun mfaNotificationId(challengeId: String): Int = stableNotificationId("mfa-$challengeId")

    /**
     * A collision-resistant id derived from [key], used for both the notification id and the
     * PendingIntent request code.
     *
     * Not `String.hashCode`: it is 32 bits designed for HashMap bucketing and is trivially
     * collidable on purpose, and a collision here means one notification replaces another while
     * `FLAG_UPDATE_CURRENT` rewrites the survivor's extras — so the tap opens the wrong message.
     * SHA-256 truncated to 31 bits stays positive (some launchers dislike negative ids).
     */
    /**
     * Ids handed out so far, so a hash collision is detected rather than silently replacing another
     * message's row in the shade.
     *
     * `stableNotificationId` truncates a hash to `Int`; two distinct messages collide often enough
     * to matter on a busy mailbox, and the symptom — a notification that vanishes when an unrelated
     * one arrives — is indistinguishable from the app being broken. Bounded, because this is
     * process-scoped bookkeeping on a delivery path.
     */
    private val assignedIds = object : LinkedHashMap<Int, String>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: Map.Entry<Int, String>): Boolean = size > MAX_TRACKED_CHALLENGES * 8
    }

    /** Records [key] against [id] and returns an id no other live key is using. */
    private fun uniqueNotificationId(key: String): Int = synchronized(assignedIds) {
        var id = stableNotificationId(key)
        var attempt = 0
        while (true) {
            val existing = assignedIds[id]
            if (existing == null || existing == key) {
                assignedIds[id] = key
                return id
            }
            // Deterministic probe, so the same key keeps resolving to the same id for as long as
            // the colliding one is still tracked — cancelling a notification has to find it again.
            attempt++
            id = stableNotificationId("$key#$attempt")
            if (attempt > 8) {
                android.util.Log.e("PushNotificationDispatcher", "Could not find a free notification id for $key")
                return id
            }
        }
        @Suppress("UNREACHABLE_CODE")
        id
    }

    internal fun stableNotificationId(key: String): Int {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
        return ((digest[0].toInt() and 0x7F) shl 24) or
            ((digest[1].toInt() and 0xFF) shl 16) or
            ((digest[2].toInt() and 0xFF) shl 8) or
            (digest[3].toInt() and 0xFF)
    }

}
