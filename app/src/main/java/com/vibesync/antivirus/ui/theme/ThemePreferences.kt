package com.vibesync.antivirus.ui.theme

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged

enum class AppTheme {
    DARK_SLATE, MIDNIGHT, OLED, LIGHT;

    fun next(): AppTheme = when (this) {
        DARK_SLATE, LIGHT -> MIDNIGHT
        MIDNIGHT -> OLED
        OLED -> DARK_SLATE
    }

    companion object {
        fun fromSaved(value: String?): AppTheme = when (value) {
            "LIGHT" -> DARK_SLATE
            else -> entries.firstOrNull { it.name == value && it != LIGHT } ?: DARK_SLATE
        }
    }
}

/**
 * Persists the active Material palette in SharedPreferences and exposes preference
 * changes as a Flow so the Compose theme can redraw immediately, including changes
 * made from another UI surface or restored when the Activity is recreated.
 */
class ThemePreferences(context: Context) {
    private val preferences: SharedPreferences = context.applicationContext
        .getSharedPreferences("safe_mobile_theme", Context.MODE_PRIVATE)

    private val key = "selected_theme"

    @OptIn(ExperimentalCoroutinesApi::class)
    val selected: Flow<AppTheme> = callbackFlow {
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { store, changedKey ->
            if (changedKey == key) {
                trySend(AppTheme.fromSaved(store.getString(key, null)))
            }
        }
        preferences.registerOnSharedPreferenceChangeListener(listener)
        trySend(AppTheme.fromSaved(preferences.getString(key, null)))
        awaitClose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
    }.distinctUntilChanged()

    suspend fun save(theme: AppTheme) {
        // apply() updates the in-process preference cache immediately and writes
        // the value durably in the background.
        preferences.edit().putString(key, (if (theme == AppTheme.LIGHT) AppTheme.DARK_SLATE else theme).name).apply()
    }
}
