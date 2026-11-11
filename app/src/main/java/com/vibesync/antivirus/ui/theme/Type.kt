package com.vibesync.antivirus.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.vibesync.antivirus.R

/**
 * Inter variable font bundled locally at res/font/inter_variable.ttf.
 * Android SansSerif remains the fallback for glyphs that Inter does not contain.
 */
@OptIn(ExperimentalTextApi::class)
private fun interFont(weight: FontWeight, axisWeight: Int): Font = Font(
    R.font.inter_variable,
    weight = weight,
    variationSettings = FontVariation.Settings(FontVariation.weight(axisWeight))
)

@OptIn(ExperimentalTextApi::class)
val InterFontFamily = FontFamily(
    interFont(FontWeight.Normal, 400),
    interFont(FontWeight.Medium, 500),
    interFont(FontWeight.SemiBold, 600),
    interFont(FontWeight.Bold, 700),
    interFont(FontWeight.ExtraBold, 800)
)

private val BaseTypography = Typography()
private val HeadingSpacing = (-0.4).sp
private val BadgeSpacing = 0.5.sp

/** Compact Material 3 type scale tuned for SafeMobile's slate, midnight and OLED surfaces. */
val AppTypography = Typography(
    displayLarge = BaseTypography.displayLarge.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.ExtraBold,
        fontSize = 24.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    displayMedium = BaseTypography.displayMedium.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 22.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    displaySmall = BaseTypography.displaySmall.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 20.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    headlineLarge = BaseTypography.headlineLarge.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.ExtraBold,
        fontSize = 24.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    headlineMedium = BaseTypography.headlineMedium.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 22.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    headlineSmall = BaseTypography.headlineSmall.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 20.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    titleLarge = BaseTypography.titleLarge.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 20.sp, lineHeight = 24.sp, letterSpacing = HeadingSpacing
    ),
    titleMedium = BaseTypography.titleMedium.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 17.sp, lineHeight = 22.sp, letterSpacing = HeadingSpacing
    ),
    titleSmall = BaseTypography.titleSmall.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Bold,
        fontSize = 15.sp, lineHeight = 20.sp, letterSpacing = HeadingSpacing
    ),
    bodyLarge = BaseTypography.bodyLarge.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 13.sp, lineHeight = 19.sp
    ),
    bodyMedium = BaseTypography.bodyMedium.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 13.sp, lineHeight = 19.sp
    ),
    bodySmall = BaseTypography.bodySmall.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.Normal,
        fontSize = 12.sp, lineHeight = 18.sp
    ),
    labelLarge = BaseTypography.labelLarge.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.ExtraBold,
        fontSize = 11.sp, lineHeight = 14.sp, letterSpacing = BadgeSpacing
    ),
    labelMedium = BaseTypography.labelMedium.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.ExtraBold,
        fontSize = 11.sp, lineHeight = 14.sp, letterSpacing = BadgeSpacing
    ),
    labelSmall = BaseTypography.labelSmall.copy(
        fontFamily = InterFontFamily, fontWeight = FontWeight.ExtraBold,
        fontSize = 10.sp, lineHeight = 13.sp, letterSpacing = BadgeSpacing
    )
)
