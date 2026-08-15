package org.kysecurity.mail.ui

import android.content.Context
import androidx.startup.Initializer
import androidx.window.embedding.RuleController
import org.kysecurity.mail.R

/**
 * Loads the split rules before the first Activity is created.
 *
 * Rules must be registered before the pair they describe is launched, and androidx.startup runs
 * this from the content-provider phase — earlier than Application.onCreate's own work and earlier
 * than any screen. On API 31, where embedding is unsupported, the rules are simply never applied.
 */
class SplitInitializer : Initializer<RuleController> {

    override fun create(context: Context): RuleController =
        RuleController.getInstance(context).apply {
            setRules(RuleController.parseRules(context, R.xml.split_config))
        }

    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}
