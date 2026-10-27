package com.vibesync.antivirus.presentation

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.ScanCompletionSummary
import com.vibesync.antivirus.ui.components.CyberCard
import java.text.DateFormat
import java.util.Date

/** Local-only visualization of actual scan counts; zero is not a "blocked" claim. */
@Composable
internal fun HomeSecurityMetrics(summary: ScanCompletionSummary?, hashDbPublishedAt: Long?) {
    val scanned = summary?.appCount ?: 0
    val flagged = summary?.threats ?: 0
    val barOne = MaterialTheme.colorScheme.primary
    val barTwo = MaterialTheme.colorScheme.error
    CyberCard(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.metrics_dashboard_title), style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.metrics_apps_scanned), color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(scanned.toString(), color = MaterialTheme.colorScheme.onSurface)
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.metrics_threats_flagged), color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(flagged.toString(), color = MaterialTheme.colorScheme.error)
            }
            // Each chart segment is scaled to the known local observed total; never invent metrics.
            Canvas(Modifier.fillMaxWidth().height(38.dp)) {
                val total = scanned.coerceAtLeast(1)
                val horizontalInset = 2.dp.toPx()
                val width = (size.width - 2 * horizontalInset).coerceAtLeast(0f)
                val h = 10.dp.toPx()
                val scannedRatio = (scanned.toFloat() / total).coerceIn(0f, 1f)
                val flaggedRatio = (flagged.toFloat() / total).coerceIn(0f, 1f)
                drawRoundRect(barOne.copy(alpha=0.18f), topLeft = Offset(horizontalInset, 2.dp.toPx()),
                    size = Size(width, h), cornerRadius = CornerRadius(5.dp.toPx()))
                drawRoundRect(barOne, topLeft = Offset(horizontalInset, 2.dp.toPx()),
                    size = Size(width * scannedRatio, h), cornerRadius = CornerRadius(5.dp.toPx()))
                drawRoundRect(barTwo.copy(alpha=0.18f), topLeft = Offset(horizontalInset, 24.dp.toPx()),
                    size = Size(width, h), cornerRadius = CornerRadius(5.dp.toPx()))
                drawRoundRect(barTwo, topLeft = Offset(horizontalInset, 24.dp.toPx()),
                    size = Size(width * flaggedRatio, h), cornerRadius = CornerRadius(5.dp.toPx()))
            }
            val updated = hashDbPublishedAt?.let { DateFormat.getDateTimeInstance().format(Date(it)) }
                ?: stringResource(R.string.metrics_database_unknown)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.metrics_database_updated), color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(updated, color = MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.labelSmall)
            }
            Text(stringResource(R.string.metrics_not_blocked_disclaimer),
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
