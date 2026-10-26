package com.vibesync.antivirus.ui.theme

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ThemePreferencesTest {
    @Test fun themeRoundTripPersistsAcrossInstances() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val first = ThemePreferences(context)
        val previous = first.selected.first()
        try {
            first.save(AppTheme.LIGHT)
            assertEquals(AppTheme.LIGHT, ThemePreferences(context).selected.first())
            first.save(AppTheme.OLED)
            assertEquals(AppTheme.OLED, ThemePreferences(context).selected.first())
        } finally {
            first.save(previous)
        }
    }

    @Test fun invalidPreferencesFallBackToMidnight() {
        assertEquals(AppTheme.MIDNIGHT, AppTheme.fromSaved(null))
        assertEquals(AppTheme.MIDNIGHT, AppTheme.fromSaved("INVALID"))
        assertEquals(AppTheme.MIDNIGHT, AppTheme.fromSaved(""))
    }
}
