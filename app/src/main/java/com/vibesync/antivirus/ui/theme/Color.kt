package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

// Light palette.
val VibeSyncLightCanvas = Color(0xFFF4F7FA)
val VibeSyncLightSurface = Color(0xFFFFFFFF)
val VibeSyncLightSurfaceVariant = Color(0xFFEDF2F7)
val VibeSyncNavy = Color(0xFF0F2942)
val VibeSyncCyberTeal = Color(0xFF0284C7)
val VibeSyncHeading = Color(0xFF0F172A)
val VibeSyncBody = Color(0xFF475569)
val VibeSyncCardBorder = Color(0xFFE2E8F0)
val SafeMobileLightSelectedContainer = Color(0xFFE0F2FE)

// Midnight palette.
val SafeMobileDarkBackground = Color(0xFF0B132B)
val SafeMobileDarkSurface = Color(0xFF1C2541)
val SafeMobileDarkSurfaceVariant = Color(0xFF283557)
val SafeMobileCyan = Color(0xFF4DA8DA)
val SafeMobileMidnightHeading = Color(0xFFF5F7FC)
val SafeMobileMidnightBody = Color(0xFFB9C6DC)
val SafeMobileMidnightBorder = Color(0xFF354366)

// OLED palette.
val SafeMobileOledHeading = Color(0xFFF7FFF9)
val SafeMobileOledBody = Color(0xFFB4C6BB)
val SafeMobileOledBorder = Color(0xFF333B36)
val SafeMobileSuccess = Color(0xFF00E676)

// Semantic verdict colors.
val VibeSyncEmerald = Color(0xFF059669)
val SafeMobileAmber = Color(0xFFF59E0B)
val SafeMobileDanger = Color(0xFFEF4444)
val SafeMobileTeal = SafeMobileCyan

val SafeMobileLightColorScheme = lightColorScheme(
    primary = VibeSyncNavy,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = VibeSyncLightSurfaceVariant,
    onPrimaryContainer = VibeSyncNavy,
    secondary = VibeSyncCyberTeal,
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = VibeSyncLightSurfaceVariant,
    onSecondaryContainer = VibeSyncNavy,
    tertiary = SafeMobileAmber,
    onTertiary = Color(0xFF3A2500),
    background = VibeSyncLightCanvas,
    onBackground = VibeSyncHeading,
    surface = VibeSyncLightSurface,
    onSurface = VibeSyncHeading,
    surfaceVariant = VibeSyncLightSurfaceVariant,
    onSurfaceVariant = VibeSyncBody,
    outline = VibeSyncCardBorder,
    outlineVariant = VibeSyncCardBorder,
    error = SafeMobileDanger,
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE4E2),
    onErrorContainer = Color(0xFF7A271A)
)

val SafeMobileDarkColorScheme = darkColorScheme(
    primary = SafeMobileCyan,
    onPrimary = Color(0xFF071827),
    primaryContainer = SafeMobileDarkSurfaceVariant,
    onPrimaryContainer = SafeMobileMidnightHeading,
    secondary = SafeMobileCyan,
    onSecondary = Color(0xFF071827),
    secondaryContainer = SafeMobileDarkSurfaceVariant,
    onSecondaryContainer = SafeMobileMidnightHeading,
    tertiary = SafeMobileAmber,
    onTertiary = Color(0xFF312000),
    background = SafeMobileDarkBackground,
    onBackground = SafeMobileMidnightHeading,
    surface = SafeMobileDarkSurface,
    onSurface = SafeMobileMidnightHeading,
    surfaceVariant = SafeMobileDarkSurfaceVariant,
    onSurfaceVariant = SafeMobileMidnightBody,
    outline = SafeMobileMidnightBorder,
    outlineVariant = SafeMobileMidnightBorder,
    error = SafeMobileDanger,
    onError = Color(0xFF320606),
    errorContainer = Color(0xFF6C161B),
    onErrorContainer = Color(0xFFFFDFE0)
)

val SafeMobileOledColorScheme = darkColorScheme(
    primary = SafeMobileSuccess,
    onPrimary = Color(0xFF001E0D),
    primaryContainer = Color(0xFF123D28),
    onPrimaryContainer = Color(0xFFB2FFD0),
    secondary = SafeMobileSuccess,
    onSecondary = Color(0xFF001E0D),
    secondaryContainer = Color(0xFF252525),
    onSecondaryContainer = SafeMobileOledHeading,
    tertiary = SafeMobileAmber,
    onTertiary = Color(0xFF312100),
    background = Color(0xFF000000),
    onBackground = SafeMobileOledHeading,
    surface = Color(0xFF121212),
    onSurface = SafeMobileOledHeading,
    surfaceVariant = Color(0xFF252525),
    onSurfaceVariant = SafeMobileOledBody,
    outline = SafeMobileOledBorder,
    outlineVariant = SafeMobileOledBorder,
    error = SafeMobileDanger,
    onError = Color(0xFF200008),
    errorContainer = Color(0xFF670A23),
    onErrorContainer = Color(0xFFFFDDE3)
)
