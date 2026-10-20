package com.vibesync.antivirus.presentation
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ads.BannerAd
import com.vibesync.antivirus.ads.ConsentManager
import com.vibesync.antivirus.ads.InterstitialAdController
import com.vibesync.antivirus.core.connectivity.ConnectivityMonitor
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.repository.ThreatRepository

private val Navy = Color(0xFF071A2C)
private val Blue = Color(0xFF123E61)
private val Cyan = Color(0xFF38C8F4)
private val Light = Color(0xFFF3F8FC)
private val Red = Color(0xFFDA3855)

@Composable
fun SafeMobileTheme(content: @Composable () -> Unit) {
 MaterialTheme(
  colorScheme = androidx.compose.material3.darkColorScheme(
   primary=Cyan, secondary=Blue, background=Navy, surface=Color(0xFF0D263C),
   onPrimary=Navy, onBackground=Light, onSurface=Light, error=Red
  ), content=content
 )
}

@Composable
fun SafeMobileScreen(repository: ThreatRepository, adsEnabled: Boolean) {
 val context = LocalContext.current
 val activity = context as? Activity
 val vm: SafeMobileViewModel = viewModel(factory = SafeMobileViewModel.Factory(repository))
 val state by vm.state.collectAsStateWithLifecycle()
 val connectivity = remember { ConnectivityMonitor(context) }
 val online by connectivity.online.collectAsStateWithLifecycle()
 var privacyAccepted by remember { mutableStateOf(context.getSharedPreferences("safe_mobile_privacy", 0).getBoolean("acknowledged", false)) }
 var privacyOptionsRequired by remember { mutableStateOf(false) }
 val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? -> uri?.let(vm::scanSelected) }
 val interstitial = remember(activity, adsEnabled) { activity?.let { InterstitialAdController(it, adsEnabled) } }

 DisposableEffect(connectivity) { connectivity.start(); onDispose { connectivity.stop() } }
 LaunchedEffect(adsEnabled, interstitial) { if (adsEnabled) interstitial?.load() }
 LaunchedEffect(state.completedScans) { if (state.completedScans > 0) interstitial?.showAfterScan(state.completedScans) }
 LaunchedEffect(Unit) { privacyOptionsRequired = activity?.let { ConsentManager.privacyOptionsRequired(it) } ?: false }

 Surface(Modifier.fillMaxSize(), color=Navy) {
  Column(Modifier.fillMaxSize()) {
   Column(
    Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal=18.dp, vertical=14.dp),
    verticalArrangement=Arrangement.spacedBy(14.dp)
   ) {
    Row(verticalAlignment=Alignment.CenterVertically) {
     Box(Modifier.size(52.dp).background(Blue, RoundedCornerShape(16.dp)), contentAlignment=Alignment.Center) {
      androidx.compose.material3.Icon(Icons.Default.Security, contentDescription=null, tint=Cyan, modifier=Modifier.size(34.dp))
     }
     Column(Modifier.padding(start=12.dp).weight(1f)) {
      Text(stringResource(R.string.brand_title), style=MaterialTheme.typography.titleLarge, fontWeight=FontWeight.Black, color=Light)
      Text(stringResource(R.string.brand_subtitle), style=MaterialTheme.typography.labelMedium, color=Cyan)
     }
    }
    if (!online) {
     Card(colors=CardDefaults.cardColors(containerColor=Color(0xFF102D45)), modifier=Modifier.fillMaxWidth()) {
      Column(Modifier.padding(14.dp), verticalArrangement=Arrangement.spacedBy(6.dp)) {
       Text(stringResource(R.string.ad_offline_title), fontWeight=FontWeight.Bold, color=Cyan)
       Text(stringResource(R.string.ad_offline_body), style=MaterialTheme.typography.bodySmall, color=Light)
       Text(stringResource(R.string.offline_label), style=MaterialTheme.typography.labelSmall, color=Color(0xFFB6CBD9))
       OutlinedButton(onClick={ openSponsor(context) }, enabled=false) { Text(stringResource(R.string.coffee_support)) }
      }
     }
    } else {
     TextButton(onClick={ openSponsor(context) }) { Text(stringResource(R.string.coffee_support)) }
    }
    Card(colors=CardDefaults.cardColors(containerColor=Color(0xFF0D263C)), shape=RoundedCornerShape(22.dp), modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(18.dp), verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Row(verticalAlignment=Alignment.CenterVertically) {
       androidx.compose.material3.Icon(if (state.threatCount>0) Icons.Default.Warning else Icons.Default.CheckCircle,
        contentDescription=null, tint=if(state.threatCount>0) Red else Cyan, modifier=Modifier.size(30.dp))
       Column(Modifier.padding(start=10.dp).weight(1f)) {
        Text(stringResource(if(state.isScanning) R.string.scan_running else if(state.threatCount>0) R.string.threat_found else R.string.scan_status),
         style=MaterialTheme.typography.titleMedium, fontWeight=FontWeight.Bold)
        Text(stringResource(R.string.signature_count,state.signatureCount,state.completedScans),
         style=MaterialTheme.typography.bodySmall, color=Color(0xFFB6CBD9))
       }
      }
      Text(stringResource(R.string.scan_explanation), style=MaterialTheme.typography.bodyMedium, color=Color(0xFFD4E0E9))
      if (state.signatureCount == 0) Text(stringResource(R.string.not_configured), style=MaterialTheme.typography.bodySmall, color=Color(0xFFFFCF8D))
      Button(onClick=vm::scanInstalled, enabled=!state.isScanning && privacyAccepted, modifier=Modifier.fillMaxWidth()) {
       if(state.isScanning) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth=2.dp, color=Navy)
       else androidx.compose.material3.Icon(Icons.Default.Security, contentDescription=null)
       Text(stringResource(if(state.isScanning) R.string.scan_running else R.string.scan_installed), modifier=Modifier.padding(start=8.dp))
      }
      OutlinedButton(onClick={ picker.launch(arrayOf("application/vnd.android.package-archive","application/octet-stream")) },
       enabled=!state.isScanning && privacyAccepted, modifier=Modifier.fillMaxWidth()) {
       androidx.compose.material3.Icon(Icons.Default.FolderOpen, contentDescription=null)
       Text(stringResource(R.string.scan_selected), modifier=Modifier.padding(start=8.dp))
      }
     }
    }
    Card(colors=CardDefaults.cardColors(containerColor=Color(0xFF102D45)), shape=RoundedCornerShape(18.dp), modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(16.dp), verticalArrangement=Arrangement.spacedBy(8.dp)) {
      Text(stringResource(R.string.monitor_title), style=MaterialTheme.typography.titleMedium, fontWeight=FontWeight.Bold)
      Text(stringResource(R.string.monitor_explanation), style=MaterialTheme.typography.bodySmall, color=Color(0xFFB6CBD9))
      OutlinedButton(onClick={
       if (!privacyAccepted) return@OutlinedButton
       if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
        context.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:"+context.packageName)))
       } else context.startForegroundService(Intent(context, com.vibesync.antivirus.core.observer.StorageSentinelService::class.java))
      }, enabled=!state.isScanning && privacyAccepted, modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.monitor_button)) }
      Text(stringResource(R.string.monitor_note), style=MaterialTheme.typography.labelSmall, color=Color(0xFFB6CBD9))
     }
    }
    state.messageResource?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=Color(0xFF102D45))) {
     Text(stringResource(message), Modifier.padding(14.dp), color=Light, style=MaterialTheme.typography.bodySmall)
    } }
    if(state.results.isNotEmpty()) {
     Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Text(stringResource(R.string.latest_results), style=MaterialTheme.typography.titleLarge, fontWeight=FontWeight.Bold)
      Text(stringResource(R.string.results_summary,
       state.results.count{it.verdict==ScanVerdict.THREAT},
       state.results.count{it.verdict==ScanVerdict.SUSPICIOUS},
       state.results.count{it.verdict==ScanVerdict.NO_MATCH}),
       color=Color(0xFFB6CBD9), style=MaterialTheme.typography.bodySmall)
      state.results.take(80).forEach { ScanResultCard(it) }
     }
    }
    Spacer(Modifier.height(8.dp))
    if (privacyOptionsRequired) TextButton(onClick={ activity?.let { ConsentManager.requestConsent(it) { } } }) { Text(stringResource(R.string.privacy_options)) }
    Text(stringResource(R.string.scan_clean_warning), style=MaterialTheme.typography.labelSmall, color=Color(0xFF8CA9BC))
   }
   if(adsEnabled) {
    Column(Modifier.fillMaxWidth().background(Color(0xFF071522)).padding(top=4.dp), horizontalAlignment=Alignment.CenterHorizontally) {
     Text(stringResource(R.string.ads_label), style=MaterialTheme.typography.labelSmall, color=Color(0xFF8CA9BC))
     BannerAd()
    }
   }
  }
 }
 if(!privacyAccepted) AlertDialog(
  onDismissRequest={},
  title={ Text(stringResource(R.string.privacy_title)) },
  text={ Text(stringResource(R.string.privacy_body)) },
  confirmButton={ TextButton(onClick={ context.getSharedPreferences("safe_mobile_privacy",0).edit().putBoolean("acknowledged",true).apply(); privacyAccepted=true }) { Text(stringResource(R.string.privacy_accept)) } },
  dismissButton={ TextButton(onClick={ activity?.finish() }) { Text(stringResource(R.string.exit_app)) } }
 )
}

private fun openSponsor(context: android.content.Context) {
 runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(BuildConfig.COFFEE_SUPPORT_URL))) }
}

@Composable
private fun ScanResultCard(result: ScanResult) {
 val color = when(result.verdict) { ScanVerdict.THREAT->Red; ScanVerdict.SUSPICIOUS->Color(0xFFFFB74D); ScanVerdict.NO_MATCH->Cyan; ScanVerdict.NOT_SCANNED->Color(0xFF9CB0BF) }
 val verdictResource = when(result.verdict) { ScanVerdict.THREAT->R.string.verdict_threat; ScanVerdict.SUSPICIOUS->R.string.verdict_suspicious; ScanVerdict.NO_MATCH->R.string.verdict_no_match; ScanVerdict.NOT_SCANNED->R.string.verdict_not_scanned }
 Card(colors=CardDefaults.cardColors(containerColor=Color(0xFF0D263C)), shape=RoundedCornerShape(14.dp), modifier=Modifier.fillMaxWidth()) {
  Column(Modifier.padding(14.dp), verticalArrangement=Arrangement.spacedBy(5.dp)) {
   Text(result.displayName, style=MaterialTheme.typography.titleSmall, fontWeight=FontWeight.Bold)
   Text(stringResource(verdictResource), color=color, style=MaterialTheme.typography.labelLarge)
   result.sha256?.let { Text(stringResource(R.string.file_hash_label,it.take(24)), style=MaterialTheme.typography.labelSmall, color=Color(0xFFB6CBD9)) }
   result.reasons.take(3).forEach { Text("• "+it, style=MaterialTheme.typography.bodySmall, color=Color(0xFFD4E0E9)) }
  }
 }
}
