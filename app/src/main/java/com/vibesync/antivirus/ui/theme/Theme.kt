package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/** Applies the persisted Dark Slate, Midnight Navy or Pure OLED palette with the bundled Inter typeface. */
@Composable
fun SafeMobileMaterialTheme(theme: AppTheme = AppTheme.DARK_SLATE, content: @Composable () -> Unit) {
    val colorScheme = when (theme) {
        AppTheme.DARK_SLATE -> SafeMobileDarkSlateColorScheme
        AppTheme.MIDNIGHT -> SafeMobileMidnightColorScheme
        AppTheme.OLED -> SafeMobileOledColorScheme
        AppTheme.LIGHT -> SafeMobileLightColorScheme
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        shapes = SafeMobileShapes,
        content = content
    )
}
