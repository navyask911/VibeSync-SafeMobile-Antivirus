package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import com.vibesync.antivirus.R
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/** Bundled, offline DM Sans under SIL OFL 1.1; Android's font fallback covers other scripts. */
val DMSans = FontFamily(
    Font(R.font.dm_sans_regular, FontWeight.Normal),
    Font(R.font.dm_sans_medium, FontWeight.Medium),
    Font(R.font.dm_sans_bold, FontWeight.Bold)
)

val SafeMobileTypography = Typography().run {
    copy(
        displayLarge = displayLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp),
        headlineLarge = headlineLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold),
        headlineMedium = headlineMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.SemiBold),
        titleLarge = titleLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.SemiBold, letterSpacing = 0.2.sp),
        titleMedium = titleMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
        bodyLarge = bodyLarge.copy(fontFamily = DMSans, lineHeight = 25.sp, letterSpacing = 0.2.sp),
        bodyMedium = bodyMedium.copy(fontFamily = DMSans, lineHeight = 22.sp, letterSpacing = 0.15.sp)
    )
}
