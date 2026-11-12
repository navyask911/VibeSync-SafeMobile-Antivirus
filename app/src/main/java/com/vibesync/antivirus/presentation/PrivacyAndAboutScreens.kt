package com.vibesync.antivirus.presentation

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ChildCare
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Draw
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.OpenInNew
import androidx.compose.material.icons.outlined.PictureAsPdf
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SettingsSuggest
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R

@Composable
internal fun PrivacyDashboardScreen() {
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.privacy_dashboard_title),
            style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.privacy_dashboard_intro),
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        PrivacyFactRow(
            icon = Icons.Outlined.Security,
            title = stringResource(R.string.privacy_package_title),
            status = stringResource(R.string.privacy_processed_locally),
            detail = stringResource(R.string.privacy_package_detail)
        )
        PrivacyFactRow(
            icon = Icons.Outlined.Lock,
            title = stringResource(R.string.privacy_hash_title),
            status = stringResource(R.string.privacy_hash_scan_status),
            detail = stringResource(R.string.privacy_hash_detail)
        )
        PrivacyFactRow(
            icon = Icons.Outlined.Description,
            title = stringResource(R.string.privacy_history_title),
            status = stringResource(R.string.privacy_stored_on_device),
            detail = stringResource(R.string.privacy_history_detail)
        )
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.privacy_dashboard_control_title),
                    style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.privacy_dashboard_control_detail),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun PrivacyFactRow(icon: ImageVector, title: String, status: String, detail: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text(title, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                Icon(Icons.Outlined.CheckCircle, contentDescription = null, tint = Color(0xFF16A34A),
                    modifier = Modifier.size(18.dp))
                Text(status, color = Color(0xFF16A34A), style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold)
            }
            Text(detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
internal fun AboutUsScreen(onOpenWebsite: () -> Unit, onOpenStore: (String) -> Unit) {
    val ecosystem = listOf(
        Triple(R.string.ecosystem_pdf_name, R.string.ecosystem_pdf_description,
            "https://play.google.com/store/apps/details?id=com.vibesync.toolkit.pdf"),
        Triple(R.string.ecosystem_drawing_name, R.string.ecosystem_drawing_description,
            "https://play.google.com/store/apps/details?id=com.navya.kids_drawing_studio"),
        Triple(R.string.ecosystem_developer_name, R.string.ecosystem_developer_description,
            "https://play.google.com/store/apps/details?id=com.utility.devoptions")
    )
    val icons = listOf(Icons.Outlined.PictureAsPdf, Icons.Outlined.Draw, Icons.Outlined.SettingsSuggest)
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(stringResource(R.string.about_us_title),
            style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.about_mission_title),
                    style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.about_mission_statement),
                    style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.about_description),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = onOpenWebsite, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.Language, contentDescription = null)
                    Text(stringResource(R.string.about_website), modifier = Modifier.padding(start = 8.dp))
                    Spacer(Modifier.weight(1f))
                    Icon(Icons.Outlined.OpenInNew, contentDescription = null)
                }
            }
        }
        Text(stringResource(R.string.ecosystem_title),
            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.ecosystem_description),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        ecosystem.forEachIndexed { index, app ->
            Surface(
                modifier = Modifier.fillMaxWidth().clickable { onOpenStore(app.third) },
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 1.dp
            ) {
                Row(
                    Modifier.padding(15.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(icons[index], contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(34.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(stringResource(app.first), style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold)
                        Text(stringResource(app.second), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2,
                            overflow = TextOverflow.Ellipsis)
                    }
                    Icon(Icons.Outlined.OpenInNew, contentDescription = stringResource(R.string.about_open_store),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
