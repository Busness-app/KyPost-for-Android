package org.kysecurity.mail.push

import android.app.Activity
import android.content.Context
import androidx.appcompat.app.AlertDialog
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.ResolvedDistributor

/**
 * Drives the UnifiedPush distributor selection + registration flow from an Activity.
 * Mirrors the flow used by the official UnifiedPush Android example: resolve first
 * to decide whether a confirmation prompt is needed, then let the library itself
 * show its own distributor picker when the choice is ambiguous (tryUseCurrentOrDefaultDistributor
 * launches that picker internally and reports the outcome via callback).
 */
object UnifiedPushRegistrar {
    private const val DEFAULT_INSTANCE = "default"

    /**
     * Begins registration. [onResult] reports whether a distributor was selected
     * and registration was requested — the endpoint itself arrives later,
     * asynchronously, via KyPostUnifiedPushService.onNewEndpoint.
     */
    fun beginRegistration(activity: Activity, onResult: (success: Boolean, error: String?) -> Unit) {
        when (UnifiedPush.resolveDefaultDistributor(activity)) {
            is ResolvedDistributor.Found -> confirmAndRegister(activity, onResult)
            ResolvedDistributor.NoneAvailable -> onResult(
                false,
                "No UnifiedPush distributor installed (install ntfy or another distributor app first)",
            )
            ResolvedDistributor.ToSelect -> {
                AlertDialog.Builder(activity)
                    .setTitle("UnifiedPush")
                    .setMessage("Choose which app should deliver your push notifications.")
                    .setPositiveButton(android.R.string.ok) { _, _ -> confirmAndRegister(activity, onResult) }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> onResult(false, null) }
                    .show()
            }
        }
    }

    private fun confirmAndRegister(activity: Activity, onResult: (success: Boolean, error: String?) -> Unit) {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(activity) { success ->
            if (success) {
                UnifiedPush.register(activity, DEFAULT_INSTANCE)
            }
            onResult(success, if (success) null else "No distributor was selected")
        }
    }

    /** Reverts to FCM: unregisters from the distributor, freeing this app's slot with it. */
    fun unregister(context: Context) {
        UnifiedPush.unregister(context, DEFAULT_INSTANCE)
    }
}
