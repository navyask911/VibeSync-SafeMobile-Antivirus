package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.GlassCard
import com.vibesync.antivirus.ui.theme.SecurityTokens

private data class DashboardFilter(val destination: String, val labelRes: Int)

private val dashboardFilters = listOf(
    DashboardFilter("home", R.string.security_filter_overview),
    DashboardFilter("apps", R.string.security_filter_apps),
    DashboardFilter("scan", R.string.security_filter_files),
    DashboardFilter("sentinel", R.string.security_filter_sentinel),
    DashboardFilter("quarantine", R.string.security_filter_vault)
)

/** Home-page navigation filters remain horizontal and one-line at all font scales. */
@Composable
internal fun SecurityDashboard(
    selectedDestination: String,
    onDestinationSelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    GlassCard(modifier = modifier.fillMaxWidth(), contentPadding = PaddingValues(0.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = stringResource(R.string.security_dashboard_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.security_dashboard_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            LazyRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 2.dp)
            ) {
                items(dashboardFilters, key = { it.destination }) { filter ->
                    FilterChip(
                        selected = selectedDestination == filter.destination,
                        onClick = { onDestinationSelected(filter.destination) },
                        shape = SecurityTokens.chipShape,
                        label = {
                            Text(
                                text = stringResource(filter.labelRes),
                                maxLines = 1,
                                softWrap = false,
                                overflow = TextOverflow.Ellipsis,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    )
                }
            }
            InstallerWarningBanner(modifier = Modifier.padding(horizontal = 12.dp))
            Spacer(Modifier.height(4.dp))
        }
    }
}
