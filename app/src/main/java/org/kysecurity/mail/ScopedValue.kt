package org.kysecurity.mail

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException

/**
 * One subscriber-scoped value in a [Preferences] DataStore: [scopeKey] travels alongside
 * [valueKey] so a change of scope (e.g. re-pairing as a different subscriber) reads back null
 * instead of the previous scope's stale value.
 */
class ScopedValue<T>(
    private val dataStore: DataStore<Preferences>,
    private val scopeKey: Preferences.Key<String>,
    private val valueKey: Preferences.Key<T>,
) {
    suspend fun get(scope: String): T? {
        val prefs = dataStore.data
            .catch { ex -> if (ex is IOException) emit(emptyPreferences()) else throw ex }
            .first()
        return if (prefs[scopeKey] == scope) prefs[valueKey] else null
    }

    suspend fun set(scope: String, value: T) {
        dataStore.edit { prefs ->
            prefs[scopeKey] = scope
            prefs[valueKey] = value
        }
    }

    /** Reads the current value and writes [transform]'s result within the same edit transaction. */
    suspend fun update(scope: String, transform: (T?) -> T) {
        dataStore.edit { prefs ->
            val current = if (prefs[scopeKey] == scope) prefs[valueKey] else null
            prefs[scopeKey] = scope
            prefs[valueKey] = transform(current)
        }
    }
}
