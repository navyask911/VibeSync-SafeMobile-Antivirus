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
        displayLarge = displayLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, fontSize = 48.sp, lineHeight = 52.sp, letterSpacing = (-1).sp),
        displayMedium = displayMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold),
        displaySmall = displaySmall.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold),
        headlineLarge = headlineLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold),
        headlineMedium = headlineMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 28.sp),
        headlineSmall = headlineSmall.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 28.sp),
        titleLarge = titleLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 28.sp),
        titleMedium = titleMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Bold, fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.sp),
        titleSmall = titleSmall.copy(fontFamily = DMSans, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 20.sp),
        bodyLarge = bodyLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 20.sp, letterSpacing = 0.sp),
        bodyMedium = bodyMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Normal, fontSize = 13.sp, lineHeight = 18.sp, letterSpacing = 0.sp),
        bodySmall = bodySmall.copy(fontFamily = DMSans, fontWeight = FontWeight.Normal, fontSize = 13.sp, lineHeight = 18.sp),
        labelLarge = labelLarge.copy(fontFamily = DMSans, fontWeight = FontWeight.Medium, fontSize = 15.sp),
        labelMedium = labelMedium.copy(fontFamily = DMSans, fontWeight = FontWeight.Medium, fontSize = 13.sp),
        labelSmall = labelSmall.copy(fontFamily = DMSans, fontWeight = FontWeight.Normal, fontSize = 13.sp)
    )
}
