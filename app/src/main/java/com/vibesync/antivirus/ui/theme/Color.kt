package com.vibesync.antivirus.ui.theme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

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
    surfaceVariant = SafeMobileDarkSurfaceVariant, onSurfaceVariant = Color(0xFFD7DFF0),
    outline = Color(0xFF8290AB), outlineVariant = Color(0xFF465470),
    error = SafeMobileDanger, onError = Color(0xFF320606),
    errorContainer = Color(0xFF6C161B), onErrorContainer = Color(0xFFFFDFE0)
)
val SafeMobileLightColorScheme = lightColorScheme(
    primary = Color(0xFF1A73E8), onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD8E8FF), onPrimaryContainer = Color(0xFF092D68),
    secondary = Color(0xFF31618A), onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFD8EAFA), onSecondaryContainer = Color(0xFF102F4C),
    tertiary = Color(0xFF865A00), onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF8F9FA), onBackground = Color(0xFF182332),
    surface = Color(0xFFFFFFFF), onSurface = Color(0xFF182332),
    surfaceVariant = Color(0xFFEDF1F5), onSurfaceVariant = Color(0xFF424E5E),
    outline = Color(0xFF687587), outlineVariant = Color(0xFFCAD2DE),
    error = Color(0xFFD93025), onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF6F120F)
)
val SafeMobileOledColorScheme = darkColorScheme(
    primary = Color(0xFF00E676), onPrimary = Color(0xFF001E0D),
    primaryContainer = Color(0xFF093820), onPrimaryContainer = Color(0xFFB2FFD0),
    secondary = Color(0xFF69EFAA), onSecondary = Color(0xFF062C18),
    secondaryContainer = Color(0xFF123D28), onSecondaryContainer = Color(0xFFC2FFD9),
    tertiary = Color(0xFFFFD166), onTertiary = Color(0xFF312100),
    background = Color(0xFF000000), onBackground = Color(0xFFF7FFF9),
    surface = Color(0xFF121212), onSurface = Color(0xFFF7FFF9),
    surfaceVariant = Color(0xFF252525), onSurfaceVariant = Color(0xFFE3EAE5),
    outline = Color(0xFF939A95), outlineVariant = Color(0xFF3D4540),
    error = Color(0xFFFF1744), onError = Color(0xFF200008),
    errorContainer = Color(0xFF670A23), onErrorContainer = Color(0xFFFFDDE3)
)
