package com.vibesync.antivirus.ui.theme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

@Composable
fun SafeMobileMaterialTheme(theme: AppTheme = AppTheme.MIDNIGHT, content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = when (theme) {
            AppTheme.MIDNIGHT -> SafeMobileDarkColorScheme
            AppTheme.LIGHT -> SafeMobileLightColorScheme
            AppTheme.OLED -> SafeMobileOledColorScheme
        },
        typography = SafeMobileTypography,
        shapes = SafeMobileShapes,
        content = content
    )
}
