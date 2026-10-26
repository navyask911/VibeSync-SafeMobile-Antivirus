package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Android's modern sans-serif family (Roboto), available offline without font downloads.
val SafeMobileTypography = Typography().run {
    copy(
        displayLarge = displayLarge.copy(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp),
        headlineLarge = headlineLarge.copy(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.Bold),
        headlineMedium = headlineMedium.copy(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold),
        titleLarge = titleLarge.copy(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold, letterSpacing = 0.2.sp),
        titleMedium = titleMedium.copy(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
        bodyLarge = bodyLarge.copy(fontFamily = FontFamily.SansSerif, lineHeight = 25.sp, letterSpacing = 0.2.sp),
        bodyMedium = bodyMedium.copy(fontFamily = FontFamily.SansSerif, lineHeight = 22.sp, letterSpacing = 0.15.sp)
    )
}
