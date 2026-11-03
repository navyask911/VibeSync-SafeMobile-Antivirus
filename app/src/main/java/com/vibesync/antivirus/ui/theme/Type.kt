package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.vibesync.antivirus.R

/** Bundled, offline DM Sans under SIL OFL 1.1; Android font fallback covers other scripts. */
val DmSansFamily = FontFamily(
    Font(R.font.dm_sans_regular, FontWeight.Normal),
    Font(R.font.dm_sans_medium, FontWeight.Medium),
    Font(R.font.dm_sans_bold, FontWeight.Bold)
)

/**
 * DM Sans is applied to every Material text style so composables using default Material
 * typography cannot silently fall back to the platform font. The five primary styles use
 * the product's v1.4.3 scale and explicit, legible line heights.
 */
val AppTypography = Typography().run {
    copy(
        displayLarge = displayLarge.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 48.sp,
            lineHeight = 52.sp
        ),
        displayMedium = displayMedium.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Bold),
        displaySmall = displaySmall.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Bold),
        headlineLarge = headlineLarge.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Bold),
        headlineMedium = headlineMedium.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp,
            lineHeight = 28.sp
        ),
        headlineSmall = headlineSmall.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp,
            lineHeight = 28.sp
        ),
        titleLarge = titleLarge.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 22.sp,
            lineHeight = 28.sp
        ),
        titleMedium = titleMedium.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 16.sp,
            lineHeight = 22.sp
        ),
        titleSmall = titleSmall.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 15.sp,
            lineHeight = 20.sp
        ),
        bodyLarge = bodyLarge.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 15.sp,
            lineHeight = 20.sp
        ),
        bodyMedium = bodyMedium.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Normal,
            fontSize = 13.sp,
            lineHeight = 18.sp
        ),
        bodySmall = bodySmall.copy(
            fontFamily = DmSansFamily,
            fontWeight = FontWeight.Normal,
            fontSize = 13.sp,
            lineHeight = 18.sp
        ),
        labelLarge = labelLarge.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Medium, fontSize = 15.sp),
        labelMedium = labelMedium.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Medium, fontSize = 13.sp),
        labelSmall = labelSmall.copy(fontFamily = DmSansFamily, fontWeight = FontWeight.Normal, fontSize = 13.sp)
    )
}
