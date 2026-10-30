package com.vibesync.antivirus.presentation

import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Biotech
import androidx.compose.material.icons.outlined.CloudDownload
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Update
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.worker.ThreatIntelligenceStats
import com.vibesync.antivirus.core.worker.ThreatIntelligenceStore
import com.vibesync.antivirus.ui.components.CyberCard
import java.text.NumberFormat
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@Composable
internal fun ThreatIntelligenceCard() {
    val app = LocalContext.current.applicationContext
    val source = remember(app) { ThreatIntelligenceStore(app.filesDir).observe() }
    val stats by source.collectAsStateWithLifecycle(initialValue = null)
    ThreatIntelligenceCardContent(stats)
}

/** Stacked metrics accommodate large fonts, RTL, and long translated labels without clipping. */
@Composable
internal fun ThreatIntelligenceCardContent(stats: ThreatIntelligenceStats?) {
    val colors = MaterialTheme.colorScheme
    val locale = LocalConfiguration.current.locales[0]
    val integers = remember(locale) { NumberFormat.getIntegerInstance(locale) }
    val percent = remember(locale) {
        NumberFormat.getPercentInstance(locale).apply { maximumFractionDigits = 2 }
    }
    CyberCard(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = colors.surface)) {
        Column(Modifier.background(Brush.linearGradient(listOf(
            colors.primaryContainer.copy(alpha = 0.55f), colors.surface
        ))).padding(18.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.background(colors.primary.copy(alpha = 0.12f), RoundedCornerShape(14.dp))
                    .padding(12.dp), contentAlignment = Alignment.Center) {
                    Icon(Icons.Outlined.Hub, contentDescription = null, tint = colors.primary,
                        modifier = Modifier.size(26.dp))
                }
                Text(stringResource(R.string.threat_intelligence_title), modifier = Modifier.weight(1f).semantics { heading() },
                    style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            }
            if (stats == null) {
                Text(stringResource(R.string.threat_intelligence_updating),
                    style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
            } else {
                IntelligenceMetric(R.string.threat_intelligence_samples, integers.format(stats.totalMalwareSamples), Icons.Outlined.Biotech)
                IntelligenceMetric(R.string.threat_intelligence_accuracy, percent.format(stats.accuracyFraction), Icons.Outlined.Insights)
                IntelligenceMetric(R.string.threat_intelligence_downloads, integers.format(stats.totalDownloads), Icons.Outlined.CloudDownload)
                val updated = remember(stats.lastUpdated, locale) {
                    runCatching {
                        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
                            .withLocale(locale).format(OffsetDateTime.parse(stats.lastUpdated)
                                .atZoneSameInstant(ZoneId.systemDefault()))
                    }.getOrElse {
                        DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale)
                            .format(LocalDate.parse(stats.lastUpdated))
                    }
                }
                IntelligenceMetric(R.string.threat_intelligence_updated, updated, Icons.Outlined.Update)
            }
            HorizontalDivider(color = colors.primary.copy(alpha = 0.15f))
            Text(stringResource(R.string.threat_intelligence_training_note),
                style = MaterialTheme.typography.bodySmall, color = colors.onSurfaceVariant)
        }
    }
}

@Composable
private fun IntelligenceMetric(@StringRes label: Int, value: String, icon: ImageVector) {
    Row(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {},
        horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(22.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(stringResource(label), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        }
    }
}
