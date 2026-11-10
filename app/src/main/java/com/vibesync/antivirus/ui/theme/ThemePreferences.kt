package com.vibesync.antivirus.ui.theme

import android.content.Context
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import java.io.IOException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

enum class AppTheme { DARK_SLATE, MIDNIGHT, OLED, LIGHT;
    companion object {
        /** Preserve Light; migrate only the retired Midnight palette to Dark Slate. */
        fun fromSaved(value: String?): AppTheme = when (value) {
            null -> DARK_SLATE
            "MIDNIGHT" -> DARK_SLATE
            else -> entries.firstOrNull { it.name == value } ?: DARK_SLATE
        }
    }
}
private val Context.safeMobileThemeStore by preferencesDataStore(name = "safe_mobile_theme")
class ThemePreferences(context: Context) {
    private val store = context.applicationContext.safeMobileThemeStore
    private val key = stringPreferencesKey("selected_theme")
    val selected: Flow<AppTheme> = store.data
        .catch { cause -> if (cause is IOException) emit(emptyPreferences()) else throw cause }
        .map { AppTheme.fromSaved(it[key]) }
    suspend fun save(theme: AppTheme) { store.edit { it[key] = theme.name } }
}
