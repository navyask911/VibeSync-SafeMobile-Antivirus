package com.vibesync.antivirus.presentation

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R

internal data class TrustPillar(
    val title: String,
    val description: String,
    val icon: ImageVector,
    val gradient: List<Color>,
    val destination: String
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun TrustPillarCarousel(
    onOpenPrivacy: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val pillars = listOf(
        TrustPillar(
            title = stringResource(R.string.trust_pillar_privacy_title),
            description = stringResource(R.string.trust_pillar_privacy_description),
            icon = Icons.Outlined.Security,
            gradient = listOf(Color(0xFF0F172A), Color(0xFF0891B2)),
            destination = "privacy"
        ),
        TrustPillar(
            title = stringResource(R.string.trust_pillar_local_title),
            description = stringResource(R.string.trust_pillar_local_description),
            icon = Icons.Outlined.Lock,
            gradient = listOf(Color(0xFF0F766E), Color(0xFF2563EB)),
            destination = "privacy"
        ),
        TrustPillar(
            title = stringResource(R.string.trust_pillar_control_title),
            description = stringResource(R.string.trust_pillar_control_description),
            icon = Icons.Outlined.Tune,
            gradient = listOf(Color(0xFF4C1D95), Color(0xFF8B5CF6)),
            destination = "settings"
        )
    )
    val pagerState = rememberPagerState(pageCount = { pillars.size })
    Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text(
            stringResource(R.string.trust_pillars_heading),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
        HorizontalPager(
            state = pagerState,
            pageSpacing = 12.dp,
            modifier = Modifier.fillMaxWidth()
        ) { page ->
            val pillar = pillars[page]
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(158.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .clickable {
                        if (pillar.destination == "settings") onOpenSettings() else onOpenPrivacy()
                    },
                shape = RoundedCornerShape(20.dp),
                color = Color.Transparent,
                shadowElevation = 2.dp
            ) {
                Box(
                    modifier = Modifier
                        .background(Brush.linearGradient(pillar.gradient))
                        .padding(18.dp)
                ) {
                    Column(
                        modifier = Modifier.align(Alignment.CenterStart),
                        verticalArrangement = Arrangement.spacedBy(7.dp)
                    ) {
                        Icon(pillar.icon, contentDescription = null, tint = Color.White, modifier = Modifier.size(30.dp))
                        Text(pillar.title, style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold, color = Color.White)
                        Text(pillar.description, style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = .9f))
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically
        ) {
            pillars.indices.forEach { index ->
                val selected = pagerState.currentPage == index
                Box(
                    modifier = Modifier
                        .padding(horizontal = 4.dp)
                        .size(if (selected) 9.dp else 6.dp)
                        .clip(CircleShape)
                        .background(if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant)
                )
            }
        }
    }
}
