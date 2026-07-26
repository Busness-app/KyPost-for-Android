package com.urlxl.mail.mail

import android.content.Context
import com.urlxl.mail.SingletonGraph
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PinnedCallFactoryProvider
import com.urlxl.mail.push.PushRuntime

class MailGraph(context: Context) {
    private val appContext = context.applicationContext
    private val mailCursorStore = MailCursorStore(appContext)
    private val pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }
    private val relaySource: MailSource = RelayMailSource(
        pairingProvider = pairingProvider,
        cursorProvider = mailCursorStore,
        pinnedCallFactory = PinnedCallFactoryProvider(
            tlsPinProvider = { PushRuntime.graph(appContext).repository.currentTlsPin() },
        ),
    )

    val repository = MailRepository(
        emailDao = DataRuntime.graph(appContext).database.emailDao(),
        relaySource = relaySource,
    )
}

object MailRuntime {
    private val holder = SingletonGraph(::MailGraph)

    fun graph(context: Context): MailGraph = holder.get(context)

    /** See [com.urlxl.mail.SingletonGraph.invalidate] — used by
     *  [com.urlxl.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}
