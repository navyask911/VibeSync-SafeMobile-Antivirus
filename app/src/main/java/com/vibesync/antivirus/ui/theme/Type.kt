package com.vibesync.antivirus.ui.theme

import android.content.Context
import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Resolve the bundled Inter static weights by Android resource name.
 *
 * Add these files under app/src/main/res/font/:
 *   inter_regular.ttf, inter_medium.ttf, inter_bold.ttf
 *
 * Dynamic resource lookup keeps source builds compilable while the font files are not yet
 * present. In that case Android SansSerif is the runtime fallback; no remote font is fetched.
 */
fun resolveInterFontFamily(context: Context): FontFamily {
    val resources = context.resources
    val packageName = context.packageName
    val regular = resources.getIdentifier("inter_regular", "font", packageName)
    val medium = resources.getIdentifier("inter_medium", "font", packageName)
    val bold = resources.getIdentifier("inter_bold", "font", packageName)

    return if (regular != 0 && medium != 0 && bold != 0) {
        FontFamily(
            Font(regular, FontWeight.Normal),
            Font(medium, FontWeight.Medium),
            Font(bold, FontWeight.Bold)
        )
    } else {
        FontFamily.SansSerif
    }
}

/** Kept as a source-compatible alias for any legacy component references. */
@Deprecated("Use resolveInterFontFamily(context)")
val DmSansFamily: FontFamily = FontFamily.SansSerif

private fun typographyFor(fontFamily: FontFamily): Typography = Typography(
    displayLarge = Typography().displayLarge.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    displayMedium = Typography().displayMedium.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    displaySmall = Typography().displaySmall.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    headlineLarge = Typography().headlineLarge.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    headlineMedium = Typography().headlineMedium.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 28.sp, lineHeight = 34.sp),
    headlineSmall = Typography().headlineSmall.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    titleLarge = Typography().titleLarge.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 26.sp),
    titleMedium = Typography().titleMedium.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 17.sp, lineHeight = 23.sp),
    titleSmall = Typography().titleSmall.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 20.sp),
    bodyLarge = Typography().bodyLarge.copy(fontFamily = fontFamily, fontWeight = FontWeight.Normal, fontSize = 17.sp, lineHeight = 24.sp),
    bodyMedium = Typography().bodyMedium.copy(fontFamily = fontFamily, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = Typography().bodySmall.copy(fontFamily = fontFamily, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 17.sp),
    labelLarge = Typography().labelLarge.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 20.sp),
    labelMedium = Typography().labelMedium.copy(fontFamily = fontFamily, fontWeight = FontWeight.Bold, fontSize = 12.sp, lineHeight = 16.sp),
    labelSmall = Typography().labelSmall.copy(fontFamily = fontFamily, fontWeight = FontWeight.Normal, fontSize = 11.sp, lineHeight = 15.sp)
)

/** Legacy fallback typography for non-composable callers. Theme uses the resolved Inter family. */
val AppTypography: Typography = typographyFor(FontFamily.SansSerif)

fun appTypography(fontFamily: FontFamily): Typography = typographyFor(fontFamily)
