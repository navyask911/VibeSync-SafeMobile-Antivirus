package com.vibesync.antivirus.presentation

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SettingsSuggest
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.AlertDialog
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R

internal fun hasSharedStorageAccess(context: Context): Boolean =
    com.vibesync.antivirus.core.observer.StorageAccessPreferences.hasAccess(context)

internal fun hasNotificationAccess(context: Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

internal object OnboardingPrefs {
    const val NAME = "safe_mobile_onboarding"
    const val COMPLETED = "completed"
    const val STEP = "step"
    const val SENTINEL_OPT_IN = "sentinel_opt_in"
    const val FIRST_SCAN_REQUESTED = "first_scan_requested"
    const val SECURITY_SETUP_V166_COMPLETED = "security_setup_v166_completed"
}

@Composable
internal fun SecurityOnboardingScreen(
    initialSyncPending: Boolean,
    onFinish: () -> Unit,
    onSkipSetup: () -> Unit
) {
    var showPermissionPrimer by rememberSaveable { mutableStateOf(false) }
    var showPrivacyDisclosure by rememberSaveable { mutableStateOf(false) }
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val appVisibilitySummary = stringResource(R.string.setup_apps_body).substringBefore('.').trimEnd() + "."
    val pagerState = rememberPagerState(pageCount = { 3 })
    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        onFinish()
    }

    val indigo = Color(0xFF312E81)
    val violet = Color(0xFF7C3AED)
    val sky = Color(0xFF0284C7)
    val blue = Color(0xFF1D4ED8)
    val emerald = Color(0xFF047857)
    val green = Color(0xFF16A34A)

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = Color.Transparent
    ) { insets ->
        if (showPermissionPrimer) {
            Box(
                modifier = Modifier.fillMaxSize()
                    .background(Brush.verticalGradient(listOf(indigo, violet)))
            ) {
                Column(
                    modifier = Modifier.fillMaxSize().padding(insets)
                        .padding(horizontal = 24.dp, vertical = 20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(
                            onClick = onSkipSetup,
                            colors = ButtonDefaults.textButtonColors(contentColor = Color.White)
                        ) { Text(stringResource(R.string.setup_skip)) }
                    }
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        color = Color.White.copy(alpha = 0.14f),
                        shape = RoundedCornerShape(24.dp)
                    ) {
                        Column(
                            Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(
                                Icons.Outlined.Security,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(58.dp)
                            )
                            Text(
                                stringResource(R.string.security_alerts_title),
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                                color = Color.White,
                                textAlign = TextAlign.Center
                            )
                            Text(
                                stringResource(R.string.incident_alerts_explanation),
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color.White.copy(alpha = 0.9f),
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                    Text(
                        appVisibilitySummary,
                        style = MaterialTheme.typography.bodyMedium,
                        color = Color.White.copy(alpha = 0.9f),
                        textAlign = TextAlign.Center,
                        maxLines = 2,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                    if (initialSyncPending) InitialSyncNotice(onGradient = true)
                    Spacer(Modifier.weight(1f))
                    Button(
                        onClick = {
                            if (hasNotificationAccess(context)) onFinish()
                            else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else onFinish()
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color.White,
                            contentColor = indigo
                        )
                    ) {
                        Text(stringResource(R.string.setup_allow_notifications))
                    }
                }
            }
        } else {
            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize(),
                pageSpacing = 0.dp
            ) { page ->
                val pageGradient = when (page) {
                    0 -> listOf(indigo, violet)
                    1 -> listOf(sky, blue)
                    else -> listOf(emerald, green)
                }
                val (icon, title, body) = when (page) {
                    0 -> Triple(
                        Icons.Outlined.Security,
                        R.string.security_dashboard_title,
                        R.string.security_scan_coverage
                    )
                    1 -> Triple(
                        Icons.Outlined.FolderOpen,
                        R.string.setup_sentinel_title,
                        R.string.setup_sentinel_body
                    )
                    else -> Triple(
                        Icons.Outlined.SettingsSuggest,
                        R.string.posture_title,
                        R.string.posture_intro
                    )
                }
                Box(
                    modifier = Modifier.fillMaxSize()
                        .background(Brush.verticalGradient(pageGradient))
                ) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(insets)
                            .padding(horizontal = 24.dp, vertical = 20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                stringResource(R.string.app_name),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            TextButton(
                                onClick = onSkipSetup,
                                colors = ButtonDefaults.textButtonColors(contentColor = Color.White)
                            ) {
                                Text(stringResource(R.string.setup_skip))
                            }
                        }
                        Spacer(Modifier.weight(1f))
                        Surface(
                            modifier = Modifier.size(168.dp),
                            color = Color.White.copy(alpha = 0.16f),
                            shape = RoundedCornerShape(40.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    icon,
                                    contentDescription = null,
                                    modifier = Modifier.size(88.dp),
                                    tint = Color.White
                                )
                            }
                        }
                        Text(
                            stringResource(title),
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            textAlign = TextAlign.Center
                        )
                        Text(
                            stringResource(body),
                            style = MaterialTheme.typography.bodyLarge,
                            textAlign = TextAlign.Center,
                            color = Color.White.copy(alpha = 0.92f)
                        )
                        Spacer(Modifier.weight(1f))
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(bottom = 2.dp)
                        ) {
                            repeat(3) { pageIndex ->
                                Box(
                                    Modifier.size(if (pagerState.currentPage == pageIndex) 10.dp else 7.dp)
                                        .background(
                                            if (pagerState.currentPage == pageIndex) Color.White
                                            else Color.White.copy(alpha = 0.42f),
                                            CircleShape
                                        )
                                )
                            }
                        }
                        if (initialSyncPending) InitialSyncNotice(onGradient = true)
                        Button(
                            onClick = {
                                if (pagerState.currentPage < 2) {
                                    coroutineScope.launch {
                                        pagerState.animateScrollToPage(pagerState.currentPage + 1)
                                    }
                                } else {
                                    showPermissionPrimer = true
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.White,
                                contentColor = pageGradient.first()
                            )
                        ) {
                            Text(
                                stringResource(
                                    if (pagerState.currentPage < 2) R.string.setup_finish
                                    else R.string.setup_allow_notifications
                                )
                            )
                        }
                        TextButton(
                            onClick = { showPrivacyDisclosure = true },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.textButtonColors(contentColor = Color.White)
                        ) {
                            Text(stringResource(R.string.privacy_title))
                        }
                    }
                }
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
private fun InitialSyncNotice(onGradient: Boolean = false) {
    androidx.compose.material3.Card(
        colors = CardDefaults.cardColors(
            containerColor = if (onGradient) Color.White.copy(alpha = 0.14f)
            else MaterialTheme.colorScheme.primaryContainer
        ),
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
                strokeWidth = 2.dp,
                color = if (onGradient) Color.White else MaterialTheme.colorScheme.primary
            )
            Text(
                stringResource(R.string.hash_database_initial_syncing),
                style = MaterialTheme.typography.bodyMedium,
                color = if (onGradient) Color.White else MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}
