package com.vibesync.antivirus.presentation

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import com.vibesync.antivirus.R
import com.vibesync.antivirus.data.local.AnalyticsWeek
import com.vibesync.antivirus.data.local.ScanAnalytics
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.ui.components.GlassCard
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import java.text.NumberFormat
import java.time.Duration
import java.time.ZonedDateTime
import java.time.format.TextStyle
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** Local Room aggregates, never telemetry. Canvas owns every chart shape; no chart dependency. */
@Composable
internal fun AnalyticsCharts(repository: ThreatRepository) {
    var week by remember { mutableStateOf(AnalyticsWeek.current()) }
    val owner = LocalLifecycleOwner.current
    LaunchedEffect(owner) {
        owner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (isActive) {
                val now = ZonedDateTime.now()
                week = AnalyticsWeek.current(now.toLocalDate(), now.zone)
                delay(Duration.between(now, now.toLocalDate().plusDays(1).atStartOfDay(now.zone))
                    .toMillis().coerceAtLeast(1_000L))
            }
        }
    }
    val source = remember(repository, week) { repository.observeAnalytics(week) }
    val data by source.collectAsStateWithLifecycle(initialValue = ScanAnalytics())
    AnalyticsChartContent(data, week)
}

@Composable
internal fun AnalyticsChartContent(data: ScanAnalytics, week: AnalyticsWeek) {
    val locale = LocalConfiguration.current.locales[0]
    val rtl = LocalLayoutDirection.current == LayoutDirection.Rtl
    val number = remember(locale) { NumberFormat.getIntegerInstance(locale) }
    val primary = MaterialTheme.colorScheme.primary
    val error = MaterialTheme.colorScheme.error
    val track = MaterialTheme.colorScheme.surfaceVariant
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val threatLabel = stringResource(R.string.metrics_threats_flagged)
    val cleanLabel = stringResource(R.string.verdict_no_match)
    val otherLabel = stringResource(R.string.analytics_other)
    val total = data.totals.threats + data.totals.noMatch + data.totals.other
    val description = listOf(stringResource(R.string.format_label_value, threatLabel, number.format(data.totals.threats)), stringResource(R.string.format_label_value, cleanLabel, number.format(data.totals.noMatch)), stringResource(R.string.format_label_value, otherLabel, number.format(data.totals.other))).joinToString("; ")
    Column(verticalArrangement = Arrangement.spacedBy(14.dp), modifier = Modifier.fillMaxWidth()) {
        GlassCard(Modifier.fillMaxWidth()) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.analytics_chart_title), style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold)
                Box(Modifier.align(Alignment.CenterHorizontally).size(170.dp).semantics { contentDescription = description },
                    contentAlignment = Alignment.Center) {
                    Canvas(Modifier.fillMaxSize().padding(8.dp)) {
                        val width = 18.dp.toPx()
                        val inset = width / 2
                        val arc = Size(size.width - width, size.height - width)
                        drawArc(track, -90f, 360f, false, Offset(inset, inset), arc, style = Stroke(width))
                        if (total > 0L) {
                            val threatAngle = (data.totals.threats.toDouble() / total * 360.0).toFloat()
                            val cleanAngle = (data.totals.noMatch.toDouble() / total * 360.0).toFloat()
                            if (threatAngle > 0) drawArc(error, -90f, threatAngle, false,
                                Offset(inset, inset), arc, style = Stroke(width, cap = StrokeCap.Butt))
                            if (cleanAngle > 0) drawArc(primary, -90f + threatAngle, cleanAngle,
                                false, Offset(inset, inset), arc, style = Stroke(width, cap = StrokeCap.Butt))
                        }
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(number.format(total), style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.analytics_total), style = MaterialTheme.typography.labelMedium)
                    }
                }
                ChartLegend(threatLabel, number.format(data.totals.threats), error)
                ChartLegend(cleanLabel, number.format(data.totals.noMatch), primary)
                ChartLegend(otherLabel, number.format(data.totals.other), muted)
                Text(stringResource(R.string.metrics_not_blocked_disclaimer), style = MaterialTheme.typography.bodySmall, color = muted)
                Text(stringResource(R.string.scan_clean_warning), style = MaterialTheme.typography.bodySmall, color = muted)
            }
        }
        GlassCard(Modifier.fillMaxWidth()) {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.analytics_weekly_scans), style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold)
                val dateFormat = remember(locale) { DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale).withDecimalStyle(java.time.format.DecimalStyle.of(locale)) }
                Text(stringResource(R.string.format_date_range, week.monday.format(dateFormat), week.monday.plusDays(6).format(dateFormat)), style = MaterialTheme.typography.labelMedium, color = muted)
                val days = week.days.map { it.dayOfWeek.getDisplayName(TextStyle.SHORT_STANDALONE, locale) }
                val bars = data.daily.take(7).let { it + List((7 - it.size).coerceAtLeast(0)) { 0L } }
                val maxCount = (bars.maxOrNull() ?: 0L).coerceAtLeast(1L)
                val textMeasurer = rememberTextMeasurer()
                val labelStyle = MaterialTheme.typography.labelSmall.copy(color = muted)
                val barDescriptions = days.zip(bars).map { (day, count) -> stringResource(R.string.format_label_value, day, number.format(count)) }
                val barDescription = barDescriptions.joinToString("; ")
                Canvas(Modifier.fillMaxWidth().height(155.dp).semantics { contentDescription = barDescription }) {
                    val top = 24.dp.toPx()
                    val plotHeight = size.height - top
                    for (line in 0..3) {
                        val y = top + plotHeight * line / 3f
                        drawLine(track, Offset(0f, y), Offset(size.width, y), 1.dp.toPx())
                    }
                    val slot = size.width / 7
                    bars.forEachIndexed { index, count ->
                        val visualIndex = if (rtl) 6 - index else index
                        val barHeight = (plotHeight * count.toDouble() / maxCount).toFloat()
                        val left = slot * visualIndex + slot * 0.23f
                        if (count > 0) drawRoundRect(primary, Offset(left, size.height - barHeight),
                            Size(slot * 0.54f, barHeight), CornerRadius(4.dp.toPx()))
                        val label = textMeasurer.measure(AnnotatedString(number.format(count)), labelStyle)
                        drawText(label, topLeft = Offset(slot * (visualIndex + 0.5f) - label.size.width / 2,
                            (size.height - barHeight - label.size.height - 4.dp.toPx()).coerceAtLeast(0f)))
                    }
                }
                Row(Modifier.fillMaxWidth()) {
                    days.forEach { day -> Box(Modifier.weight(1f), contentAlignment = Alignment.TopCenter) {
                        Text(day, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.labelSmall)
                    } }
                }
                Text(stringResource(R.string.analytics_week_note), style = MaterialTheme.typography.bodySmall, color = muted)
            }
        }
    }
}

@Composable
private fun ChartLegend(label: String, count: String, color: androidx.compose.ui.graphics.Color) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Canvas(Modifier.size(8.dp)) { drawCircle(color) }
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Text(count, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = color)
    }
}
