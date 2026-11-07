package com.vibesync.antivirus.presentation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SettingsSuggest
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.AlertDialog
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import kotlinx.coroutines.launch

/** Four-step, swipeable setup. Each permission remains optional and is requested only on tap. */
@Composable
internal fun SecuritySetupScreen(
    initialSyncPending: Boolean,
    notificationsGranted: Boolean,
    globalDefenseEnabled: Boolean,
    folderAccessGranted: Boolean,
    batteryOptimizationExempt: Boolean,
    initialPage: Int = 0,
    onRequestNotifications: () -> Unit,
    onToggleGlobalDefense: (Boolean) -> Unit,
    onChooseFolder: () -> Unit,
    onReviewOverlayAccess: () -> Unit,
    onRequestBatteryOptimization: () -> Unit,
    onFinish: () -> Unit,
    onSkipSetup: () -> Unit
) {
    var showPrivacyDisclosure by rememberSaveable { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()
    val pagerState = rememberPagerState(
        initialPage = initialPage.coerceIn(0, 3),
        pageCount = { 4 }
    )

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background
    ) { insets ->
        Column(
            modifier = Modifier.fillMaxSize().padding(insets).padding(horizontal = 24.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onSkipSetup) { Text(stringResource(R.string.setup_skip)) }
            }
            Icon(
                Icons.Default.Security,
                contentDescription = stringResource(R.string.app_name),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(48.dp)
            )
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.setup_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.setup_step_progress, pagerState.currentPage + 1),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary
            )

            HorizontalPager(
                state = pagerState,
                modifier = Modifier.weight(1f).fillMaxWidth(),
                pageSpacing = 14.dp
            ) { page ->
                val icon = when (page) {
                    0 -> Icons.Default.Notifications
                    1 -> Icons.Default.Security
                    2 -> Icons.Default.FolderOpen
                    else -> Icons.Default.SettingsSuggest
                }
                val title = when (page) {
                    0 -> R.string.setup_notifications_title
                    1 -> R.string.global_threat_intelligence_title
                    2 -> R.string.setup_storage_title
                    else -> R.string.battery_review_title
                }
                val description = when (page) {
                    0 -> R.string.setup_notifications_body
                    1 -> R.string.global_threat_intelligence_description
                    2 -> R.string.setup_storage_body
                    else -> R.string.battery_review_body
                }
                Card(
                    modifier = Modifier.fillMaxSize().padding(vertical = 18.dp),
                    shape = RoundedCornerShape(28.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                ) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(22.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Surface(
                            modifier = Modifier.size(144.dp),
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = RoundedCornerShape(32.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    icon,
                                    contentDescription = null,
                                    modifier = Modifier.size(72.dp),
                                    tint = MaterialTheme.colorScheme.secondary
                                )
                            }
                        }
                        Spacer(Modifier.height(22.dp))
                        Text(
                            stringResource(title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center
                        )
                        Spacer(Modifier.height(10.dp))
                        Text(
                            stringResource(description),
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(24.dp))
                        when (page) {
                            0 -> Button(
                                onClick = onRequestNotifications,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(stringResource(
                                    if (notificationsGranted) R.string.setup_permission_granted
                                    else R.string.setup_allow_notifications
                                ))
                            }
                            1 -> Switch(
                                checked = globalDefenseEnabled,
                                onCheckedChange = onToggleGlobalDefense
                            )
                            2 -> Button(
                                onClick = onChooseFolder,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(stringResource(
                                    if (folderAccessGranted) R.string.setup_permission_granted
                                    else R.string.setup_allow_storage
                                ))
                            }
                            else -> Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                OutlinedButton(
                                    onClick = onReviewOverlayAccess,
                                    modifier = Modifier.fillMaxWidth()
                                ) { Text(stringResource(R.string.posture_overlays)) }
                                Button(
                                    onClick = onRequestBatteryOptimization,
                                    enabled = !batteryOptimizationExempt,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(stringResource(
                                        if (batteryOptimizationExempt) R.string.setup_permission_granted
                                        else R.string.battery_review_action
                                    ))
                                }
                                Text(
                                    stringResource(R.string.posture_overlay_power),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    }
                }
            }

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(bottom = 14.dp)
            ) {
                repeat(4) { page ->
                    Box(
                        Modifier.size(if (pagerState.currentPage == page) 9.dp else 7.dp)
                            .background(
                                if (pagerState.currentPage == page) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.outlineVariant,
                                CircleShape
                            )
                    )
                }
            }
            if (initialSyncPending) InitialSyncNotice()
            Button(
                onClick = {
                    if (pagerState.currentPage < 3) {
                        coroutineScope.launch { pagerState.animateScrollToPage(pagerState.currentPage + 1) }
                    } else {
                        onFinish()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(
                    if (pagerState.currentPage < 3) R.string.setup_continue
                    else R.string.setup_finish
                ))
            }
            TextButton(
                onClick = { showPrivacyDisclosure = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.privacy_title))
            }
        }
    }

    if (showPrivacyDisclosure) {
        AlertDialog(
            onDismissRequest = { showPrivacyDisclosure = false },
            title = { Text(stringResource(R.string.privacy_title)) },
            text = { Text(stringResource(R.string.ad_privacy_intro)) },
            confirmButton = {
                TextButton(onClick = { showPrivacyDisclosure = false }) {
                    Text(stringResource(R.string.close))
                }
            }
        )
    }
}

@Composable
private fun InitialSyncNotice() {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            androidx.compose.material3.CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp
            )
            Text(
                stringResource(R.string.hash_database_initial_syncing),
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}
