package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

@Composable
fun SafeMobileMaterialTheme(darkTheme: Boolean, content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) SafeMobileDarkColorScheme else SafeMobileLightColorScheme,
        typography = SafeMobileTypography,
        shapes = SafeMobileShapes,
        content = content
    )
}
