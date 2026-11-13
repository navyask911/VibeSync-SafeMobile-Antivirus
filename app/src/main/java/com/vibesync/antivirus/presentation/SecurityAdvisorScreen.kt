package com.vibesync.antivirus.presentation

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R

@Composable
internal fun SecurityAdvisorScreen(
    state: ProtectionAdvisorState,
    onOpenIssue: (AdvisorIssueItem) -> Unit,
    onSnooze: (String) -> Unit,
    onRestore: (String) -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.security_advisor_heading), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.v140_pending_actions, state.pendingCount), style = MaterialTheme.typography.headlineMedium)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.ui_score_title), style = MaterialTheme.typography.titleLarge)
                Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(state.score.toString(), style = MaterialTheme.typography.displayLarge, color = MaterialTheme.colorScheme.primary)
                    Text(stringResource(R.string.ui_score_out_of_100), style = MaterialTheme.typography.bodyMedium)
                }
                Text(stringResource(R.string.ui_score_checks, state.pendingCount, state.issues.size), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.ui_score_explanation), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        AdvisorAccordion(
            titleResource = R.string.v140_critical,
            items = state.critical,
            onOpenIssue = onOpenIssue,
            onSnooze = onSnooze,
            onRestore = onRestore
        )
        if (state.minor.isNotEmpty()) {
            AdvisorAccordion(
                titleResource = R.string.v140_minor,
                items = state.minor,
                onOpenIssue = onOpenIssue,
                onSnooze = onSnooze,
                onRestore = onRestore
            )
        }
        if (state.snoozed.isNotEmpty()) {
            AdvisorAccordion(
                titleResource = R.string.v140_snoozed,
                items = state.snoozed,
                onOpenIssue = onOpenIssue,
                onSnooze = onSnooze,
                onRestore = onRestore
            )
        }
        AdvisorAccordion(
            titleResource = R.string.v140_completed,
            items = state.completed,
            onOpenIssue = onOpenIssue,
            onSnooze = onSnooze,
            onRestore = onRestore
        )
    }
}

@Composable
private fun AdvisorAccordion(
    titleResource: Int,
    items: List<AdvisorIssueItem>,
    onOpenIssue: (AdvisorIssueItem) -> Unit,
    onSnooze: (String) -> Unit,
    onRestore: (String) -> Unit
) {
    var expanded by rememberSaveable(titleResource) { mutableStateOf(items.isNotEmpty()) }
    Card(
        modifier = Modifier.fillMaxWidth().animateContentSize(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(titleResource), style = MaterialTheme.typography.titleMedium)
                    Text(items.size.toString(), style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Icon(
                    if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                    contentDescription = null
                )
            }
            AnimatedVisibility(expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items.forEach { item ->
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalArrangement = Arrangement.spacedBy(7.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    stringResource(item.titleResource),
                                    modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.titleMedium
                                )
                                if (item.group == AdvisorIssueGroup.COMPLETED) {
                                    Surface(
                                        color = Color(0xFFE5F5EA),
                                        contentColor = Color(0xFF16753A),
                                        shape = RoundedCornerShape(50)
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Icon(Icons.Outlined.CheckCircle, contentDescription = null)
                                            Text(stringResource(R.string.v140_completed), style = MaterialTheme.typography.labelMedium,
                                                fontWeight = FontWeight.Bold)
                                        }
                                    }
                                } else {
                                    Surface(
                                        color = MaterialTheme.colorScheme.errorContainer,
                                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                                        shape = RoundedCornerShape(50)
                                    ) {
                                        Text(
                                            "−${item.points} pts",
                                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }
                            Text(stringResource(R.string.v140_security_risk_explained), style = MaterialTheme.typography.titleSmall)
                            Text(stringResource(item.detailResource), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (item.destination != "scan") {
                                    Button(
                                        onClick = { onOpenIssue(item) },
                                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp)
                                    ) {
                                        Text(stringResource(
                                            when (item.destination) {
                                                "sentinel" -> R.string.ui_sentinel_setup
                                                "posture" -> R.string.posture_refresh
                                                "capabilities" -> R.string.detection_capabilities_title
                                                "guardian" -> R.string.guardian_review_settings
                                                else -> R.string.posture_fix
                                            }
                                        ))
                                    }
                                }
                                if (item.group == AdvisorIssueGroup.SNOOZED) {
                                    OutlinedButton(
                                        onClick = { onRestore(item.id) },
                                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp)
                                    ) {
                                        Text(
                                            stringResource(R.string.v140_done_return_to_audit),
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                } else if (item.canSnooze && item.group != AdvisorIssueGroup.COMPLETED) {
                                    OutlinedButton(
                                        onClick = { onSnooze(item.id) },
                                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp)
                                    ) {
                                        Text(
                                            stringResource(R.string.v140_snooze_warning),
                                            maxLines = 2,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                } else if (item.group == AdvisorIssueGroup.COMPLETED) {
                                    Text(
                                        stringResource(R.string.v140_done_return_to_audit),
                                        color = MaterialTheme.colorScheme.tertiary,
                                        style = MaterialTheme.typography.labelLarge
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
