package com.vibesync.antivirus.presentation

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import kotlinx.coroutines.launch

data class TrustPillar(
    val title: String,
    val description: String,
    val icon: ImageVector?,
    val gradient: List<Color>,
    val destination: String
)

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
internal fun TrustPillarCarousel(
    onOpenPrivacyDashboard: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val pillars = listOf(
        TrustPillar(
            stringResource(R.string.trust_pillar_privacy_title),
            stringResource(R.string.trust_pillar_privacy_body),
            Icons.Outlined.Shield,
            listOf(Color(0xFF102A43), Color(0xFF00B8D9)),
            "privacy"
        ),
        TrustPillar(
            stringResource(R.string.trust_pillar_local_title),
            stringResource(R.string.trust_pillar_local_body),
            Icons.Outlined.Lock,
            listOf(Color(0xFF087F8C), Color(0xFF2563EB)),
            "privacy"
        ),
        TrustPillar(
            stringResource(R.string.trust_pillar_control_title),
            stringResource(R.string.trust_pillar_control_body),
            null,
            listOf(Color(0xFF3B176C), Color(0xFF8B5CF6)),
            "settings"
        )
    )
    val pagerState = rememberPagerState(pageCount = { pillars.size })
    val scope = rememberCoroutineScope()
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                stringResource(R.string.trust_pillars_heading),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
            Text(
                stringResource(R.string.trust_pillars_hint),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        HorizontalPager(
            state = pagerState,
            pageSpacing = 12.dp,
            contentPadding = PaddingValues(end = 28.dp),
            modifier = Modifier.fillMaxWidth()
        ) { page ->
            val pillar = pillars[page]
            Column(
                Modifier.fillMaxWidth()
                    .heightIn(min = 164.dp)
                    .clip(RoundedCornerShape(20.dp))
                    .background(Brush.linearGradient(pillar.gradient))
                    .clickable {
                        if (pillar.destination == "settings") onOpenSettings()
                        else onOpenPrivacyDashboard()
                    }
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (pillar.icon != null) {
                    Icon(pillar.icon, contentDescription = pillar.title, tint = Color.White, modifier = Modifier.size(30.dp))
                } else {
                    Canvas(Modifier.size(30.dp)) {
                        val stroke = 2.5.dp.toPx()
                        val radius = 3.5.dp.toPx()
                        val rails = listOf(size.height * .2f, size.height * .5f, size.height * .8f)
                        val knobs = listOf(size.width * .34f, size.width * .7f, size.width * .45f)
                        rails.forEachIndexed { index, y ->
                            drawLine(Color.White, androidx.compose.ui.geometry.Offset(0f, y),
                                androidx.compose.ui.geometry.Offset(size.width, y), strokeWidth = stroke)
                            drawCircle(Color.White, radius = radius,
                                center = androidx.compose.ui.geometry.Offset(knobs[index], y))
                        }
                    }
                }
                Text(
                    pillar.title,
                    color = Color.White,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    pillar.description,
                    color = Color.White.copy(alpha = .92f),
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    stringResource(R.string.trust_pillar_open),
                    color = Color.White,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
            pillars.indices.forEach { page ->
                Surface(
                    Modifier.padding(horizontal = 3.dp).size(if (pagerState.currentPage == page) 18.dp else 6.dp, 6.dp)
                        .clip(CircleShape).clickable { scope.launch { pagerState.animateScrollToPage(page) } },
                    color = if (pagerState.currentPage == page) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.outlineVariant,
                    shape = CircleShape
                ) {}
            }
        }
    }
}

@Composable
internal fun PrivacyDashboardScreen(onOpenAboutUs: () -> Unit = {}) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.privacy_dashboard_title), style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.privacy_dashboard_intro), style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        PrivacyDataPoint(
            stringResource(R.string.privacy_package_name),
            stringResource(R.string.privacy_processed_locally)
        )
        PrivacyDataPoint(
            stringResource(R.string.privacy_file_hash),
            stringResource(R.string.privacy_hash_not_uploaded_by_default)
        )
        PrivacyDataPoint(
            stringResource(R.string.privacy_scan_history),
            stringResource(R.string.privacy_stored_on_device)
        )
        Surface(
            Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(16.dp)
        ) {
            Text(
                stringResource(R.string.privacy_optional_sharing_note),
                Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        OutlinedButton(onClick = onOpenAboutUs, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.privacy_learn_about_us))
        }
    }
}

@Composable
private fun PrivacyDataPoint(label: String, value: String) {
    Surface(
        Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(Icons.Outlined.CheckCircle, contentDescription = null,
                tint = Color(0xFF159B62), modifier = Modifier.size(24.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
internal fun AboutUsScreen() {
    val uriHandler = LocalUriHandler.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.about_us_title), style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold)
        Surface(
            Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.surface,
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(stringResource(R.string.about_mission_label), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.about_mission_statement), style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.about_description_label), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.about_description), style = MaterialTheme.typography.bodyMedium)
                OutlinedButton(onClick = { uriHandler.openUri("https://vibesyncro.com/") }) {
                    Text(stringResource(R.string.about_website))
                    Spacer(Modifier.width(6.dp))
                    Icon(Icons.Outlined.OpenInNew, contentDescription = null, modifier = Modifier.size(16.dp))
                }
            }
        }
        Text(stringResource(R.string.about_ecosystem_heading), style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold)
        EcosystemAppCard(
            stringResource(R.string.about_app_pdf_title),
            stringResource(R.string.about_app_pdf_description),
            "https://play.google.com/store/apps/details?id=com.vibesync.toolkit.pdf",
            uriHandler::openUri
        )
        EcosystemAppCard(
            stringResource(R.string.about_app_drawing_title),
            stringResource(R.string.about_app_drawing_description),
            "https://play.google.com/store/apps/details?id=com.navya.kids_drawing_studio",
            uriHandler::openUri
        )
        EcosystemAppCard(
            stringResource(R.string.about_app_developer_title),
            stringResource(R.string.about_app_developer_description),
            "https://play.google.com/store/apps/details?id=com.utility.devoptions",
            uriHandler::openUri
        )
    }
}

@Composable
private fun EcosystemAppCard(title: String, description: String, url: String, onOpen: (String) -> Unit) {
    Surface(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable { onOpen(url) },
        color = MaterialTheme.colorScheme.surface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(description, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(Icons.Outlined.OpenInNew, contentDescription = stringResource(R.string.about_open_app),
                tint = MaterialTheme.colorScheme.primary)
        }
    }
}

data class NotificationIncidentDetails(
    val fileName: String,
    val filePath: String,
    val reason: String,
    val status: String,
    val sourcePackage: String?,
    val fileUri: String?,
    val sha256: String?
)

@Composable
internal fun ThreatDetailsDialog(
    details: NotificationIncidentDetails,
    onDismiss: () -> Unit,
    onScan: () -> Unit,
    onDelete: () -> Unit,
    onWhitelist: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.notification_details_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailValue(stringResource(R.string.notification_file_label), details.fileName)
                DetailValue(stringResource(R.string.notification_path_label), details.filePath)
                DetailValue(stringResource(R.string.notification_reason_label), details.reason)
                DetailValue(stringResource(R.string.notification_status_label), details.status)
                details.sourcePackage?.let {
                    DetailValue(stringResource(R.string.notification_source_label), it)
                }
                details.sha256?.let { DetailValue(stringResource(R.string.privacy_file_hash), it) }
            }
        },
        confirmButton = {
            Column(horizontalAlignment = Alignment.End) {
                TextButton(onClick = onScan) { Text(stringResource(R.string.notification_scan_action)) }
                TextButton(onClick = onDelete, enabled = details.fileUri != null || details.sourcePackage != null) { Text(stringResource(R.string.notification_delete_action)) }
                TextButton(onClick = onWhitelist, enabled = details.sourcePackage != null) {
                    Text(stringResource(R.string.notification_whitelist_action))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        }
    )
}

@Composable
private fun DetailValue(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Text(value.ifBlank { "—" }, style = MaterialTheme.typography.bodySmall,
            maxLines = 4, overflow = TextOverflow.Ellipsis)
    }
}
