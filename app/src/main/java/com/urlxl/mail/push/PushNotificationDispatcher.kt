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
        // Fails CLOSED: if the lock state can't be read, redact. Defaulting to "unlocked" turned a
        // storage or Keystore error into exactly the disclosure this gate exists to prevent.
        runCatching { SecurityRuntime.graph(context).appLockManager.locked.value }.getOrDefault(true)

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
        MfaChallengeTracker(context).markDelivered(payload.challengeId)
        if (!notificationsAllowed(context)) return

        val notificationId = mfaNotificationId(payload.challengeId)

        val tapIntent = Intent(context, MfaApprovalActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_MFA_CHALLENGE_ID, payload.challengeId)
            // The context the user needs to tell their own sign-in from an attacker's. Safe in
            // Intent extras: MfaApprovalActivity is not exported, so only this app can supply
            // them, and MfaChallengeTracker still gates on the id having really been pushed.
            .putExtra(EXTRA_MFA_IP, payload.ipAddress)
            .putExtra(EXTRA_MFA_LOCATION, payload.approxLocation)
            .putExtra(EXTRA_MFA_USER_AGENT, payload.userAgent)
            .putExtra(EXTRA_MFA_ISSUED_AT, payload.issuedAtEpochMs)
            .putExtra(EXTRA_MFA_MATCH_DIGITS, payload.matchDigits)
            .putExtra(EXTRA_MFA_DECOY_DIGITS, payload.decoyDigits.toTypedArray())
        val tapPendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, MFA_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.mfa_notification_title))
            .setContentText(context.getString(R.string.mfa_notification_body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setGroup(MFA_GROUP_KEY)
            // Silent, not suppressed: a burst of challenges still all appear (none is lost) but
            // only the first one in the window makes a sound.
            .setSilent(MfaAlertWindow.shouldSuppressAlert())
            .setContentIntent(tapPendingIntent)
            .build()

        postNotification(context, notificationId, notification)
    }

    /**
     * Single exit point for posting, so the POST_NOTIFICATIONS check and the failure handling live
     * in one place.
     *
     * [notificationsAllowed] is still the gate, but the permission can be revoked between that check
     * and this call, and both call sites run on FCM/UnifiedPush delivery threads where an uncaught
     * `SecurityException` takes out the message handler rather than merely dropping one notification.
     */
    private fun postNotification(context: Context, id: Int, notification: android.app.Notification) {
        if (!notificationsAllowed(context)) return
        try {
            NotificationManagerCompat.from(context).notify(id, notification)
        } catch (e: SecurityException) {
            android.util.Log.w("PushNotifications", "POST_NOTIFICATIONS revoked; dropping notification", e)
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
     * A collision-resistant id derived from [key].
     *
     * `String.hashCode` was used for both the notification id and the PendingIntent request code.
     * It is a 32-bit value designed for HashMap bucketing, not distinctness — and it is trivially
     * collidable on purpose. Two colliding message ids meant the second notification *replaced*
     * the first, and `FLAG_UPDATE_CURRENT` rewrote the first's extras to point at the second
     * message, so tapping the survivor opened the wrong email.
     *
     * SHA-256 truncated to 31 bits keeps the value positive (some launchers dislike negative ids)
     * and pushes the collision probability out past any plausible number of live notifications.
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
