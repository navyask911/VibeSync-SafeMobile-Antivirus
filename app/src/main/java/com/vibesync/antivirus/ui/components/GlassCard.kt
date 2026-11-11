package com.vibesync.antivirus.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.ui.theme.SecurityTokens

/**
 * Low-alpha dark glass-style surface with a subtle security-accent border.
 * This intentionally uses alpha composition rather than RenderEffect; a real blur can be
 * added with the Haze library if desired without breaking Android 12 rendering.
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable () -> Unit
) {
    Surface(
        modifier = modifier,
        shape = SecurityTokens.cardShape,
        color = MaterialTheme.colorScheme.surface.copy(alpha = SecurityTokens.glassSurfaceAlpha),
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = SecurityTokens.glassBorderAlpha)),
        tonalElevation = SecurityTokens.cardElevation,
        shadowElevation = SecurityTokens.cardElevation
    ) {
        Box(modifier = Modifier.padding(contentPadding)) {
            content()
        }
    }
}
