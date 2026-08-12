package org.kysecurity.mail.mail

import android.content.Context
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PinnedCallFactoryProvider
import org.kysecurity.mail.push.PushRuntime

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

    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}
