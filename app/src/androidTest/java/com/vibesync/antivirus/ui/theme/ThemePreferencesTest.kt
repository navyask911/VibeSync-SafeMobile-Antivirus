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
            first.save(AppTheme.DARK_SLATE)
            assertEquals(AppTheme.DARK_SLATE, ThemePreferences(context).selected.first())
            first.save(AppTheme.OLED)
            assertEquals(AppTheme.OLED, ThemePreferences(context).selected.first())
        } finally {
            first.save(previous)
        }
    }

    @Test fun invalidAndLegacyLightPreferencesFallBackToDarkSlate() {
        assertEquals(AppTheme.DARK_SLATE, AppTheme.fromSaved(null))
        assertEquals(AppTheme.DARK_SLATE, AppTheme.fromSaved("INVALID"))
        assertEquals(AppTheme.DARK_SLATE, AppTheme.fromSaved(""))
        assertEquals(AppTheme.DARK_SLATE, AppTheme.fromSaved("LIGHT"))
    }

    @Test fun threeTierCycleIsSeamless() {
        assertEquals(AppTheme.MIDNIGHT, AppTheme.DARK_SLATE.next())
        assertEquals(AppTheme.OLED, AppTheme.MIDNIGHT.next())
        assertEquals(AppTheme.DARK_SLATE, AppTheme.OLED.next())
    }
}
