package com.urlxl.mail.push

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
import com.urlxl.mail.MainActivity
import com.urlxl.mail.R
import com.urlxl.mail.security.SecurityRuntime

object PushNotificationDispatcher : com.urlxl.mail.ProcessScopedState {
    private const val CHANNEL_ID = "kypost_push"
    private const val MFA_CHANNEL_ID = "kypost_mfa"
    private const val MFA_GROUP_KEY = "com.urlxl.mail.push.MFA"

    /** Repeat MFA challenges inside this window post silently instead of alerting again — the
     *  client-side half of MFA-fatigue resistance (the server caps minting rate). */
    private const val MFA_ALERT_COOLDOWN_MS = 5 * 60 * 1000L

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
     * [cancelMfaChallenge] used to recompute `mfaNotificationId(challengeId)`, which is only correct
     * outside a burst — during one, every challenge shares [MFA_BURST_NOTIFICATION_ID]. So answering
     * or burning a challenge mid-flood cancelled a notification that had never been posted and left
     * the burst row sitting in the shade pointing at a dead challenge. That is a bug that exists
     * *only* during an MFA-fatigue flood, i.e. only in the scenario this whole feature is for.
     *
     * Bounded by the same ceiling as the tracker: entries are removed on cancel, but a challenge
     * that is never answered would otherwise linger for the life of the process.
     */
    private val postedNotificationIds = object : LinkedHashMap<String, Int>(16, 0.75f, false) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Int>): Boolean = size > MAX_TRACKED_CHALLENGES
    }

    /**
     * The challenge the burst summary currently points at, or null when no burst row is showing.
     *
     * A burst posts ONE notification whose `PendingIntent` is rewritten (`FLAG_UPDATE_CURRENT`) to
     * the newest challenge each time. The previous occupant is then unreachable from the UI — but it
     * stayed marked deliverable in [MfaChallengeTracker] for five minutes, so up to
     * [MAX_TRACKED_CHALLENGES] challenges were answerable while exactly one had ever been shown.
     * [MfaApprovalActivity] treats "tracked" as "the user was really shown this", and that invariant
     * was simply false in burst mode. Revoking the outgoing one keeps it true.
     */
    @Volatile
    private var burstChallengeId: String? = null

    init {
        // Both fields above are account-scoped bookkeeping in a process that AppRestart no longer
        // kills: a stale burst pointer or a stale posted-id map outlives an unpair and then makes
        // the next session cancel the wrong notification. See [com.urlxl.mail.ProcessScopedState].
        com.urlxl.mail.ProcessState.register(this)
    }

    override fun resetForNewSession() {
        synchronized(postedNotificationIds) {
            postedNotificationIds.clear()
            burstChallengeId = null
        }
    }

    const val EXTRA_MFA_CHALLENGE_ID = "challengeId"
    const val EXTRA_MFA_IP = "mfaIpAddress"
    const val EXTRA_MFA_LOCATION = "mfaApproxLocation"
    const val EXTRA_MFA_USER_AGENT = "mfaUserAgent"
    const val EXTRA_MFA_ISSUED_AT = "mfaIssuedAt"
    const val EXTRA_MFA_MATCH_DIGITS = "mfaMatchDigits"
    const val EXTRA_MFA_DECOY_DIGITS = "mfaDecoyDigits"
    const val EXTRA_MESSAGE_ID = "com.urlxl.mail.push.EXTRA_MESSAGE_ID"
    const val EXTRA_SENDER = "com.urlxl.mail.push.EXTRA_SENDER"
    const val EXTRA_SUBJECT = "com.urlxl.mail.push.EXTRA_SUBJECT"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
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
     * True when the app lock is engaged, i.e. the correct PIN/biometric has not been presented in
     * this process. Notification *content* is gated on this: sender and subject on a lock screen
     * defeat "Require Unlock to Open" entirely, and used to be posted with `BigTextStyle` and no
     * visibility setting regardless of every security toggle the user had turned on.
     */
    private fun isLocked(context: Context): Boolean =
        // Fails CLOSED, and uses isLockedNow() rather than locked.value: this runs on a
        // push-delivery thread in a backgrounded process, the one place where the grace window may
        // have expired with nothing having called lockNow() yet.
        runCatching { SecurityRuntime.graph(context).appLockManager.isLockedNow() }.getOrDefault(true)

    fun show(context: Context, payload: PushPayload) {
        ensureChannel(context)
        if (!notificationsAllowed(context)) return

        val locked = isLocked(context)

        val launchIntent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_MESSAGE_ID, payload.messageId)
            .putExtra(EXTRA_SENDER, payload.senderName)
            .putExtra(EXTRA_SUBJECT, payload.emailSubject)

        val notificationId = stableNotificationId("mail-${payload.messageId}")
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val title = if (locked) context.getString(R.string.app_name) else PushPayloadParser.title(payload)
        val body = if (locked) context.getString(R.string.notification_hidden_while_locked) else PushPayloadParser.body(payload)

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(body)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(if (locked) NotificationCompat.VISIBILITY_SECRET else NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(pendingIntent)
        if (!locked) builder.setStyle(NotificationCompat.BigTextStyle().bigText(body))

        postNotification(context, notificationId, builder.build())
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
     *
     * Each challenge also gets its own notification id. Distinct challenges used to be coalesced
     * onto one shared id, so answering either one cancelled the notification for both and the
     * second challenge silently disappeared — in a feature built to resist MFA fatigue.
     */
    fun showMfaChallenge(context: Context, payload: MfaChallengePayload) {
        val tracker = PushRuntime.graph(context).mfaChallengeTracker
        val burst = tracker.liveCount() >= MFA_BURST_THRESHOLD
        val silent = tracker.shouldSuppressAlert(MFA_ALERT_COOLDOWN_MS)
        // Tracked (below) only once a notification for it is actually on screen. Marking first
        // meant that with POST_NOTIFICATIONS denied — or any SecurityException on the way out — the
        // challenge became answerable for five minutes with nothing ever shown to the user, which
        // is the pretext an approval screen must not be reachable under.
        val notificationId = postMfaNotification(context, payload, burst, silent) ?: return

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
            approxLocation = intent.getStringExtra(EXTRA_MFA_LOCATION).orEmpty(),
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
            .putExtra(EXTRA_MFA_LOCATION, payload.approxLocation)
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
    internal fun stableNotificationId(key: String): Int {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray())
        return ((digest[0].toInt() and 0x7F) shl 24) or
            ((digest[1].toInt() and 0xFF) shl 16) or
            ((digest[2].toInt() and 0xFF) shl 8) or
            (digest[3].toInt() and 0xFF)
    }

}
