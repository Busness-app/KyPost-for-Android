package com.urlxl.mail.data

import android.content.Context
import androidx.room.Room
import com.urlxl.mail.SingletonGraph
import com.urlxl.mail.security.HostileLocationSettings

class DataGraph(context: Context) {
    private val appContext = context.applicationContext

    /**
     * In-memory when Hostile Location Protection is on (see the 2026-07-22 security-hardening
     * spec) — every repository/DAO is unchanged either way, since both builders produce the
     * same [AppDatabase] type; only where its rows live differs. Toggling the setting requires
     * an app relaunch ([com.urlxl.mail.security.AppRestart]) since this decision is only made
     * once, at construction time.
     */
    val database: AppDatabase = if (HostileLocationSettings(appContext).isEnabled()) {
        Room.inMemoryDatabaseBuilder(appContext, AppDatabase::class.java).build()
    } else {
        Room.databaseBuilder(appContext, AppDatabase::class.java, "kypost_mail.db")
            .addMigrations(
                AppDatabase.MIGRATION_1_2,
                AppDatabase.MIGRATION_2_3,
                AppDatabase.MIGRATION_3_4,
                AppDatabase.MIGRATION_4_5,
                AppDatabase.MIGRATION_5_6,
                AppDatabase.MIGRATION_6_7,
                AppDatabase.MIGRATION_7_8,
            )
            .build()
    }
}

/** Standalone singleton, kept independent of PushGraph/KyPostApp — mirrors how PushGraph itself
 *  stands alone rather than nesting inside another graph. */
object DataRuntime {
    private val holder = SingletonGraph(::DataGraph)

    fun graph(context: Context): DataGraph = holder.get(context)

    /** See [com.urlxl.mail.SingletonGraph.invalidate] — used by
     *  [com.urlxl.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()

    /** See [com.urlxl.mail.SingletonGraph.take] — used by
     *  [com.urlxl.mail.security.SecurityWipe.closeAndDeleteDatabase], which has to close the
     *  database instance that is actually in use, not a freshly built stand-in. */
    fun takeGraph(): DataGraph? = holder.take()
}
