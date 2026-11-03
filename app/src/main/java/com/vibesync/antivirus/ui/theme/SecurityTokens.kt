package com.vibesync.antivirus.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Shared layout tokens for all three Figma themes; Material color roles stay theme-resolved. */
object SecurityTokens {
    // Retained for GlassCard, which continues to be used by existing settings panels.
    val glassTint = Color(0xFFFFFFFF)
    val glassBorder = Color(0xFFE2E8F0)
    const val glassSurfaceAlpha = 0.94f
    const val glassBorderAlpha = 0.22f
    val pageHorizontalPadding: Dp = 20.dp
    val pageTopPadding: Dp = 8.dp
    val sectionSpacing: Dp = 20.dp
    val cardContentPadding: Dp = 18.dp
    val cardInnerSpacing: Dp = 12.dp
    val cardElevation: Dp = 0.dp
    val cardBorderWidth: Dp = 1.dp
    val cardShape = RoundedCornerShape(20.dp)
    val tileShape = RoundedCornerShape(16.dp)
    val iconTileShape = RoundedCornerShape(12.dp)
    val chipShape = RoundedCornerShape(50)

    // Verdicts always retain a text label as well as their semantic hue.
    val threat = Color(0xFFB42318)
    val suspicious = Color(0xFF925E00)
    val noMatch = Color(0xFF475569)
    val notScanned = Color(0xFF64748B)
}
