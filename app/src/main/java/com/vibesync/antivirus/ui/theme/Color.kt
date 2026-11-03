package com.vibesync.antivirus.ui.theme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

// Figma uses one component structure with separate Light, Midnight and OLED palettes.
val SafeMobileDarkBackground = Color(0xFF0B132B)
val SafeMobileDarkSurface = Color(0xFF1C2541)
val SafeMobileDarkSurfaceVariant = Color(0xFF283557)
val SafeMobileCyan = Color(0xFF4DA8DA)
val SafeMobileTeal = Color(0xFF71C4E6)
val SafeMobileAmber = Color(0xFFFFD166)
val SafeMobileDanger = Color(0xFFFF5252)
val SafeMobileSuccess = Color(0xFF00E676)

val SafeMobileDarkColorScheme = darkColorScheme(
    primary = SafeMobileCyan, onPrimary = Color(0xFF001F34),
    primaryContainer = Color(0xFF173655), onPrimaryContainer = Color(0xFFD8F1FF),
    secondary = SafeMobileTeal, onSecondary = Color(0xFF032C42),
    secondaryContainer = Color(0xFF17435C), onSecondaryContainer = Color(0xFFE0F6FF),
    tertiary = SafeMobileAmber, onTertiary = Color(0xFF3A2C02),
    background = SafeMobileDarkBackground, onBackground = Color(0xFFF5F7FC),
    surface = SafeMobileDarkSurface, onSurface = Color(0xFFF5F7FC),
    surfaceVariant = SafeMobileDarkSurfaceVariant, onSurfaceVariant = Color(0xFFB9C6DC),
    outline = Color(0xFF354366), outlineVariant = Color(0xFF354366),
    error = SafeMobileDanger, onError = Color(0xFF320606),
    errorContainer = Color(0xFF6C161B), onErrorContainer = Color(0xFFFFDFE0)
)
val VibeSyncLightCanvas = Color(0xFFF4F7FA)
val VibeSyncLightSurface = Color(0xFFFFFFFF)
val VibeSyncLightSurfaceVariant = Color(0xFFEDF2F7)
val VibeSyncNavy = Color(0xFF0F2942)
val VibeSyncCyberTeal = Color(0xFF0284C7)
val VibeSyncEmerald = Color(0xFF059669)
val VibeSyncHeading = Color(0xFF0F172A)
val VibeSyncBody = Color(0xFF475569)
val VibeSyncCardBorder = Color(0xFFE2E8F0)

val SafeMobileLightColorScheme = lightColorScheme(
    primary = VibeSyncNavy, onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE3EEF7), onPrimaryContainer = VibeSyncNavy,
    secondary = VibeSyncCyberTeal, onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDDF2FC), onSecondaryContainer = Color(0xFF073B57),
    tertiary = VibeSyncEmerald, onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFDDF7EC), onTertiaryContainer = Color(0xFF064E3B),
    background = VibeSyncLightCanvas, onBackground = VibeSyncHeading,
    surface = VibeSyncLightSurface, onSurface = VibeSyncHeading,
    surfaceVariant = VibeSyncLightSurfaceVariant, onSurfaceVariant = VibeSyncBody,
    outline = VibeSyncCardBorder, outlineVariant = VibeSyncCardBorder,
    error = Color(0xFFB42318), onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE4E2), onErrorContainer = Color(0xFF7A271A)
)
val SafeMobileOledColorScheme = darkColorScheme(
    primary = Color(0xFF00E676), onPrimary = Color(0xFF001E0D),
    primaryContainer = Color(0xFF093820), onPrimaryContainer = Color(0xFFB2FFD0),
    secondary = Color(0xFF69EFAA), onSecondary = Color(0xFF062C18),
    secondaryContainer = Color(0xFF123D28), onSecondaryContainer = Color(0xFFC2FFD9),
    tertiary = Color(0xFFFFD166), onTertiary = Color(0xFF312100),
    background = Color(0xFF000000), onBackground = Color(0xFFF7FFF9),
    surface = Color(0xFF121212), onSurface = Color(0xFFF7FFF9),
    surfaceVariant = Color(0xFF252525), onSurfaceVariant = Color(0xFFB4C6BB),
    outline = Color(0xFF333B36), outlineVariant = Color(0xFF333B36),
    error = Color(0xFFFF1744), onError = Color(0xFF200008),
    errorContainer = Color(0xFF670A23), onErrorContainer = Color(0xFFFFDDE3)
)
