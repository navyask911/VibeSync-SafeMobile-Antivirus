package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.security.DeviceOwnerManager
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import java.text.DateFormat
import java.util.Date

@Composable
internal fun EnterpriseProtectionCard(manager: DeviceOwnerManager, modifier: Modifier = Modifier) {
 val owner by manager.isDeviceOwner.collectAsState()
 var guide by remember { mutableStateOf(false) }
 LaunchedEffect(Unit) { manager.refreshState() }
 Card(modifier.fillMaxWidth(),shape=RoundedCornerShape(16.dp),colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) {
  Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
   Text(stringResource(R.string.enterprise_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.SemiBold)
   Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(8.dp)) {
    androidx.compose.material3.Icon(if(owner) Icons.Default.CheckCircle else Icons.Default.Warning,null,
     tint=if(owner) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary)
    Text(stringResource(if(owner) R.string.enterprise_status_owner else R.string.enterprise_status_standard),
     style=MaterialTheme.typography.labelLarge,color=if(owner) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary)
   }
   Text(stringResource(R.string.enterprise_body),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
   Text(stringResource(R.string.incident_user_confirmation), style=MaterialTheme.typography.bodySmall,
    color=MaterialTheme.colorScheme.onSurfaceVariant)
   OutlinedButton(onClick={guide=true},modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.enterprise_setup_guide)) }
  }
 }
 if(guide) AlertDialog(onDismissRequest={guide=false},title={Text(stringResource(R.string.enterprise_setup_guide))},
  text={Text(stringResource(R.string.enterprise_setup_instructions))},
  confirmButton={TextButton(onClick={guide=false}) { Text(stringResource(R.string.close)) }})

}

@Composable
internal fun InstallSourceAuditPanel(
 incidents: List<SecurityIncidentEntity>,
 onScan: () -> Unit,
 onInspect: (String) -> Unit,
 onUninstall: (String) -> Unit
) {
 Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
  Text(stringResource(R.string.install_sources_title),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Bold)
  Text(stringResource(R.string.install_sources_body),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  val rows=incidents.filter { it.eventKind=="PACKAGE_INSTALL" || it.eventKind=="PACKAGE_UPDATED" }
  if(rows.isEmpty()) {
   Text(stringResource(R.string.install_sources_empty),style=MaterialTheme.typography.titleMedium)
   Text(stringResource(R.string.install_sources_empty_body),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
   OutlinedButton(onClick=onScan) { Text(stringResource(R.string.security_scan_now)) }
  } else rows.take(30).forEach { event ->
   val play=event.status.startsWith("PLAY_STORE")
   val external=event.status.startsWith("EXTERNAL")
   Card(Modifier.fillMaxWidth(),shape=RoundedCornerShape(16.dp),colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface)) {
    Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(5.dp)) {
     Text(event.sourcePackage ?: stringResource(R.string.unknown_file),style=MaterialTheme.typography.titleSmall,fontWeight=FontWeight.SemiBold)
     Text(stringResource(if(play) R.string.install_source_play_badge else if(external) R.string.install_source_external_badge else R.string.install_source_unknown_badge),
      style=MaterialTheme.typography.labelMedium,color=if(play) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary)
     Text(DateFormat.getDateTimeInstance(DateFormat.SHORT,DateFormat.SHORT).format(Date(event.occurredAt)),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
     Text(event.reason.take(1200),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
     if(!event.sha256Hash.isNullOrBlank()) Text(stringResource(R.string.file_hash_label,event.sha256Hash.take(24)),style=MaterialTheme.typography.labelSmall)
     Text(event.actionTaken + " · " + event.status.substringAfter("|","SOURCE_RECORDED"),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
     event.sourcePackage?.takeIf { it.isNotBlank() }?.let { packageName ->
      Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
       OutlinedButton(onClick={onInspect(packageName)}) { Text(stringResource(R.string.app_info_label)) }
       Button(onClick={onUninstall(packageName)}) { Text(stringResource(R.string.uninstall_app)) }
      }
     }
    }
   }
  }
 }
}


@Composable
internal fun EnterpriseOnboardingNotice(manager: DeviceOwnerManager) {
 val owner by manager.isDeviceOwner.collectAsState()
 var guide by remember { mutableStateOf(false) }
 LaunchedEffect(Unit) { manager.refreshState() }
 Card(
  modifier=Modifier.fillMaxWidth(),
  shape=RoundedCornerShape(16.dp),
  colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)
 ) {
  Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(5.dp)) {
   Text(stringResource(R.string.enterprise_title),style=MaterialTheme.typography.titleSmall,fontWeight=FontWeight.SemiBold)
   Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(6.dp)) {
    androidx.compose.material3.Icon(if(owner) Icons.Default.CheckCircle else Icons.Default.Warning,null,
     tint=if(owner) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary)
    Text(stringResource(if(owner) R.string.enterprise_status_owner else R.string.enterprise_status_standard),
     style=MaterialTheme.typography.labelMedium)
   }
   Text(stringResource(R.string.enterprise_body),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
   TextButton(onClick={guide=true}) { Text(stringResource(R.string.enterprise_setup_guide)) }
  }
 }
 if(guide) AlertDialog(onDismissRequest={guide=false},title={Text(stringResource(R.string.enterprise_setup_guide))},
  text={Text(stringResource(R.string.enterprise_setup_instructions))},
  confirmButton={TextButton(onClick={guide=false}) { Text(stringResource(R.string.close)) }})
}

