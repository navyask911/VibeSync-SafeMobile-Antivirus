package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

/** One palette for every entry point; system/light preferences cannot override production dark. */
@Composable
fun SafeMobileMaterialTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SafeMobileDarkColorScheme,
        typography = SafeMobileTypography,
        shapes = SafeMobileShapes,
        content = content
    )
}
