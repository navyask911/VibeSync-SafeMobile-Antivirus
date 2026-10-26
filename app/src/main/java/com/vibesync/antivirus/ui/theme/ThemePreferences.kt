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

enum class AppTheme { MIDNIGHT, LIGHT, OLED;
    companion object {
        fun fromSaved(value: String?): AppTheme = entries.firstOrNull { it.name == value } ?: MIDNIGHT
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
