package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color

val SafeMobileDarkBackground = Color(0xFF0F172A)
val SafeMobileDarkSurface = Color(0xFF1E293B)
val SafeMobileDarkSurfaceVariant = Color(0xFF273449)
val SafeMobileCyan = Color(0xFF06B6D4)
val SafeMobileTeal = Color(0xFF38BDF8)
val SafeMobileAmber = Color(0xFFFBBF24)
val SafeMobileDanger = Color(0xFFF87171)
val SafeMobileSuccess = Color(0xFF4ADE80)

val SafeMobileDarkColorScheme = darkColorScheme(
    primary = SafeMobileCyan, onPrimary = Color(0xFF002F38),
    primaryContainer = Color(0xFF164E63), onPrimaryContainer = Color(0xFFCFFAFE),
    secondary = SafeMobileTeal, onSecondary = Color(0xFF082F49),
    secondaryContainer = Color(0xFF0C4A6E), onSecondaryContainer = Color(0xFFE0F2FE),
    tertiary = SafeMobileAmber, onTertiary = Color(0xFF422006),
    background = SafeMobileDarkBackground, onBackground = Color(0xFFF1F5F9),
    surface = SafeMobileDarkSurface, onSurface = Color(0xFFF1F5F9),
    surfaceVariant = SafeMobileDarkSurfaceVariant, onSurfaceVariant = Color(0xFFCBD5E1),
    surfaceTint = Color.Transparent,
    outline = Color(0xFF64748B), outlineVariant = Color(0xFF334155),
    error = SafeMobileDanger, onError = Color(0xFF450A0A),
    errorContainer = Color(0xFF7F1D1D), onErrorContainer = Color(0xFFFEE2E2)
)
