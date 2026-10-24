package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.GlassCard
import com.vibesync.antivirus.ui.components.SecurityStatusCard

/** Home dashboard with compact single-line chips and the existing accessible scan summary. */
@Composable
internal fun SecurityDashboard(
    status: String,
    description: String,
    lastScanLabel: String,
    threatCount: Int,
    signatureCount: Int,
    scanning: Boolean,
    progress: Float?,
    hasScanned: Boolean,
    cleanResult: Boolean,
    onScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    androidx.compose.foundation.layout.Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        GlassCard(modifier = Modifier.fillMaxWidth(), contentPadding = 0.dp) {
            val labels = listOf(
                stringResource(R.string.dashboard_chip_offline),
                stringResource(R.string.dashboard_chip_post_install),
                stringResource(R.string.dashboard_chip_on_device)
            )
            LazyRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp)
            ) {
                items(labels) { label ->
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                    ) {
                        Text(
                            text = label,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
            Text(
                stringResource(R.string.dashboard_post_install_description),
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        SecurityStatusCard(
            status = status,
            description = description,
            lastScanLabel = lastScanLabel,
            threatCount = threatCount,
            signatureCount = signatureCount,
            scanning = scanning,
            progress = progress,
            hasScanned = hasScanned,
            cleanResult = cleanResult,
            onScan = onScan
        )
    }
}
