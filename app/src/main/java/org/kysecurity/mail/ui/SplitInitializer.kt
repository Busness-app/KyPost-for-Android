package org.kysecurity.mail.ui

import android.content.Context
import androidx.startup.Initializer
import androidx.window.embedding.RuleController
import org.kysecurity.mail.R

// Rules must be registered before the pair they describe launches; androidx.startup runs earliest.
class SplitInitializer : Initializer<RuleController> {

    override fun create(context: Context): RuleController =
        RuleController.getInstance(context).apply {
            setRules(RuleController.parseRules(context, R.xml.split_config))
        }

    override fun dependencies(): List<Class<out Initializer<*>>> = emptyList()
}
