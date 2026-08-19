package org.kysecurity.mail.push

import android.app.Activity
import android.content.Context
import androidx.appcompat.app.AlertDialog
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.ResolvedDistributor
import org.kysecurity.mail.security.showSecurely

/** Drives UnifiedPush distributor selection; the library shows its own picker when ambiguous. */
object UnifiedPushRegistrar {
    private const val DEFAULT_INSTANCE = "default"

    /** [onResult] reports selection only; the endpoint arrives later via onNewEndpoint. */
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
                    .create()
                    .showSecurely()
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
