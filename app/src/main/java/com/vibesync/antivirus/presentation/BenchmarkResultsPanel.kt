package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard as Card
import java.util.Locale
import org.json.JSONObject

/**
 * Displays only verified metrics from the copy of docs/BENCHMARK_REPORT.md embedded at build time.
 * The app never downloads benchmark reports or test APKs, and cannot edit benchmark data.
 */
@Composable
internal fun BenchmarkResultsPanel() {
    val ctx = LocalContext.current
    val document = remember(ctx) {
        runCatching {
            val text = ctx.assets.open("benchmark-report.md").bufferedReader().use { it.readText() }
            val raw = text.substringAfter("~~~json", "")
                .substringBefore("~~~", "").trim()
            JSONObject(raw)
        }.getOrNull()
    }
    val measured = document?.optString("status") == "MEASURED" &&
        document.optInt("total_apps", -1) == 200 &&
        document.optInt("benign_apps", -1) == 100 &&
        document.optInt("malicious_apps", -1) == 100 &&
        document.optInt("not_scanned", -1) == 0 &&
        listOf("tpr_percent", "fpr_percent", "mean_latency_ms")
            .all { key -> !document.isNull(key) && document.has(key) && document.optDouble(key, Double.NaN).isFinite() }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.benchmark_title), style = MaterialTheme.typography.titleMedium)
            if (!measured) {
                Text(stringResource(R.string.benchmark_not_measured),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall)
            } else {
                val report = requireNotNull(document)
                BenchmarkMetric(stringResource(R.string.benchmark_total_apps), report.optInt("total_apps").toString())
                BenchmarkMetric(stringResource(R.string.benchmark_tpr),
                    String.format(Locale.getDefault(), "%.2f%%", report.optDouble("tpr_percent")))
                BenchmarkMetric(stringResource(R.string.benchmark_fpr),
                    String.format(Locale.getDefault(), "%.2f%%", report.optDouble("fpr_percent")))
                BenchmarkMetric(stringResource(R.string.benchmark_latency),
                    String.format(Locale.getDefault(), "%.1f ms", report.optDouble("mean_latency_ms")))
            }
            Text(stringResource(R.string.benchmark_privacy_note),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun BenchmarkMetric(label: String, value: String) {
    Text("$label: $value", style = MaterialTheme.typography.bodyMedium)
}
