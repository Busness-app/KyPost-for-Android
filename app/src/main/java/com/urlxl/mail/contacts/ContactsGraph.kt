package com.urlxl.mail.contacts

import android.content.Context
import com.urlxl.mail.SingletonGraph
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.push.pinnedPairingCallFactory

class ContactsGraph(context: Context) {
    private val appContext = context.applicationContext
    private val database = DataRuntime.graph(appContext).database

    // Shared with both clients below — see finding C2 of the 2026-07-22 security-hardening
    // spec's final-review fix round: contact/group sync used to default to the plain unpinned
    // pairingHttpClient() even though it sends the same deviceSecret bearer credential as mail.
    private val pinnedCallFactory = pinnedPairingCallFactory(appContext)

    val repository = ContactSyncRepository(
        db = database,
        client = ContactSyncClient(callFactory = pinnedCallFactory),
        cursorStore = ContactCursorStore(appContext, database),
        pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() },
    )
    val coordinator = ContactSyncCoordinator(repository)
    val groupSyncRepository = GroupSyncRepository(
        db = database,
        client = GroupsSyncClient(callFactory = pinnedCallFactory),
        pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() },
    )
}

object ContactsRuntime {
    private val holder = SingletonGraph(::ContactsGraph)

    fun graph(context: Context): ContactsGraph = holder.get(context)

    /** See [com.urlxl.mail.SingletonGraph.invalidate] — used by
     *  [com.urlxl.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}
