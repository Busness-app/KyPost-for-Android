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

object PushNotificationDispatcher {
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
        ensureMfaChannel(context)
        val tracker = MfaChallengeTracker(context)
        val burst = tracker.liveCount() >= MFA_BURST_THRESHOLD

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
            .setSilent(MfaAlertWindow.shouldSuppressAlert())
            .setContentIntent(tapPendingIntent)
            .build()

        // Tracked only once a notification for it is actually on screen. Marking first meant that
        // with POST_NOTIFICATIONS denied — or any SecurityException on the way out — the challenge
        // became answerable for five minutes with nothing ever shown to the user, which is the
        // pretext an approval screen must not be reachable under.
        if (postNotification(context, notificationId, notification)) {
            tracker.markDelivered(payload.challengeId)
        }
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

    fun cancelMfaChallenge(context: Context, challengeId: String) {
        NotificationManagerCompat.from(context).cancel(mfaNotificationId(challengeId))
    }

    private fun notificationsAllowed(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun mfaNotificationId(challengeId: String): Int = stableNotificationId("mfa-$challengeId")

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

    /** Tracks only whether the *sound* for an MFA notification was played recently. It no longer
     *  holds a notification id, so it can't cause one challenge's answer to dismiss another's. */
    private object MfaAlertWindow {
        private var lastAlertAtEpochMs: Long = 0L

        @Synchronized
        fun shouldSuppressAlert(nowEpochMs: Long = System.currentTimeMillis()): Boolean {
            val suppress = lastAlertAtEpochMs != 0L && nowEpochMs - lastAlertAtEpochMs <= MFA_ALERT_COOLDOWN_MS
            if (!suppress) lastAlertAtEpochMs = nowEpochMs
            return suppress
        }
    }
}
