package com.vibesync.antivirus.presentation

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard

/** Persistent reminder only: never auto-opens settings or prevents normal dashboard use. */
@Composable
internal fun FullScreenAlertPermissionCard(onOpenSettings: () -> Unit) {
    CyberCard(modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenSettings),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.error)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Default.NotificationsActive, null, tint = MaterialTheme.colorScheme.onErrorContainer)
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.full_screen_dashboard_warning), fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onErrorContainer)
                Text(stringResource(R.string.full_screen_dashboard_fallback), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }
    }
}

@Composable
internal fun SystemAppProtectionBadge() {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Icon(Icons.Default.VerifiedUser, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
        Text(stringResource(R.string.system_app_protection_badge), style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary)
    }
}
