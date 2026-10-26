package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

val SafeMobileDarkBackground = Color(0xFF121212)
val SafeMobileDarkSurface = Color(0xFF191D24)
val SafeMobileDarkSurfaceVariant = Color(0xFF252D38)
val SafeMobileCyan = Color(0xFF00E5FF)
val SafeMobileTeal = Color(0xFF448AFF)
val SafeMobileAmber = Color(0xFFFFB74D)
val SafeMobileDanger = Color(0xFFFF5252)
val SafeMobileSuccess = Color(0xFF00E676)

val SafeMobileDarkColorScheme = darkColorScheme(
    primary = SafeMobileCyan, onPrimary = SafeMobileDarkBackground,
    primaryContainer = Color(0xFF003944), onPrimaryContainer = Color(0xFFB3F5FF),
    secondary = SafeMobileTeal, onSecondary = SafeMobileDarkBackground,
    secondaryContainer = Color(0xFF163B35), onSecondaryContainer = Color(0xFFC0FFF0),
    tertiary = SafeMobileAmber, onTertiary = Color(0xFF271900),
    background = SafeMobileDarkBackground, onBackground = Color(0xFFF3F7FA),
    surface = SafeMobileDarkSurface, onSurface = Color(0xFFF3F7FA),
    surfaceVariant = SafeMobileDarkSurfaceVariant, onSurfaceVariant = Color(0xFFC0CBD4),
    error = SafeMobileDanger, onError = Color(0xFF240608)
)
val SafeMobileLightColorScheme = lightColorScheme(
    primary = Color(0xFF00897B), onPrimary = Color.White,
    primaryContainer = Color(0xFFB2DFDB), onPrimaryContainer = Color(0xFF00201C),
    secondary = Color(0xFF00695C), onSecondary = Color.White,
    secondaryContainer = Color(0xFFB2DFDB), onSecondaryContainer = Color(0xFF00201C),
    tertiary = Color(0xFF8A5700), onTertiary = Color.White,
    background = Color(0xFFF7F9FC), onBackground = Color(0xFF142326),
    surface = Color.White, onSurface = Color(0xFF142326),
    surfaceVariant = Color(0xFFE4F0EF), onSurfaceVariant = Color(0xFF3F5452),
    error = Color(0xFFB3261E), onError = Color.White
)

