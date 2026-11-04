package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

/** Applies the persisted Light, Midnight or OLED palette and the bundled Inter typeface. */
@Composable
fun SafeMobileMaterialTheme(theme: AppTheme = AppTheme.LIGHT, content: @Composable () -> Unit) {
    val context = LocalContext.current
    val interFamily = remember(context) { resolveInterFontFamily(context) }
    val colorScheme = when (theme) {
        AppTheme.LIGHT -> SafeMobileLightColorScheme
        AppTheme.MIDNIGHT -> SafeMobileDarkColorScheme
        AppTheme.OLED -> SafeMobileOledColorScheme
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = appTypography(interFamily),
        shapes = SafeMobileShapes,
        content = content
    )
}
