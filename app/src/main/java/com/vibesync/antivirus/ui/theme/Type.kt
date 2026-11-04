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
 * Official Inter variable font bundled locally at res/font/inter_variable.ttf.
 * The variable weight axis is applied explicitly, so regular, medium, semibold and
 * bold text all use their intended Inter weights. Android SansSerif remains the
 * fallback for glyphs not present in Inter.
 */
@OptIn(ExperimentalTextApi::class)
private fun interFont(weight: FontWeight, axisWeight: Int): Font = Font(
    R.font.inter_variable,
    weight = weight,
    variationSettings = FontVariation.Settings(
        FontVariation.weight(axisWeight)
    )
)

@OptIn(ExperimentalTextApi::class)
val InterFontFamily = FontFamily(
    interFont(FontWeight.Normal, 400),
    interFont(FontWeight.Medium, 500),
    interFont(FontWeight.SemiBold, 600),
    interFont(FontWeight.Bold, 700)
)

/** Product type scale: 28 / 20 / 17 / 14 / 12 / 11 sp. */
val AppTypography = Typography(
    displayLarge = Typography().displayLarge.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    displayMedium = Typography().displayMedium.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    displaySmall = Typography().displaySmall.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    headlineLarge = Typography().headlineLarge.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    headlineMedium = Typography().headlineMedium.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    headlineSmall = Typography().headlineSmall.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    titleLarge = Typography().titleLarge.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    titleMedium = Typography().titleMedium.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 17.sp, lineHeight = 23.sp),
    titleSmall = Typography().titleSmall.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 20.sp),
    bodyLarge = Typography().bodyLarge.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Normal, fontSize = 17.sp, lineHeight = 24.sp),
    bodyMedium = Typography().bodyMedium.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = Typography().bodySmall.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 17.sp),
    labelLarge = Typography().labelLarge.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 20.sp),
    labelMedium = Typography().labelMedium.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Bold, fontSize = 12.sp, lineHeight = 16.sp),
    labelSmall = Typography().labelSmall.copy(fontFamily = InterFontFamily, fontWeight = FontWeight.Normal, fontSize = 11.sp, lineHeight = 15.sp)
)
