package com.vibesync.antivirus.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Shared styling primitives for the security dashboard's restrained glass-surface treatment. */
object SecurityTokens {
    val glassTint = Color(0xFF1E293B)
    val glassBorder = Color(0xFF06B6D4)
    const val glassSurfaceAlpha = 0.94f
    const val glassBorderAlpha = 0.22f
    val cardElevation: Dp = 0.dp
    val cardShape = RoundedCornerShape(16.dp)
    val chipShape = RoundedCornerShape(50)
}

