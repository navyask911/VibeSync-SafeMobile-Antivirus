package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/** Applies the persisted Light, Midnight or OLED palette with the bundled Inter typeface. */
@Composable
fun SafeMobileMaterialTheme(theme: AppTheme = AppTheme.LIGHT, content: @Composable () -> Unit) {
    val colorScheme = when (theme) {
        AppTheme.LIGHT -> SafeMobileLightColorScheme
        AppTheme.MIDNIGHT -> SafeMobileDarkColorScheme
        AppTheme.OLED -> SafeMobileOledColorScheme
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        shapes = SafeMobileShapes,
        content = content
    )
}
