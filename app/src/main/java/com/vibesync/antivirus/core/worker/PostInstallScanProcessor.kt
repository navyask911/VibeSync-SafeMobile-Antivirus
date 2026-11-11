package com.vibesync.antivirus.core.worker

import android.content.Context
import android.util.Log
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.BloomFilterScanner
import com.vibesync.antivirus.core.engine.DexPatternScanner
import com.vibesync.antivirus.core.engine.PermissionModelScorer
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.engine.StaticAnalyzer
import com.vibesync.antivirus.core.engine.ThreatVerdict
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
import com.vibesync.antivirus.core.security.IntegrityChecker
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import com.vibesync.antivirus.core.security.TrustedAppStore
import com.vibesync.antivirus.core.security.InstallSourceVerifier
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.observer.InstallScanNotifications
import com.vibesync.antivirus.core.observer.InstallSourceNotifier
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

/** Serial local scan shared by the live sentinel and its durable WorkManager fallback. */
internal object PostInstallScanProcessor {
 private val scanLock = Mutex()

 suspend fun scan(context: Context, name: String, eventId: String, updated: Boolean) = scanLock.withLock {
  if (TrustedAppStore(context).isTrusted(name)) {
   InstallScanNotifications.finish(context, eventId)
   return@withLock
  }
  val app = context.applicationContext as? SafeMobileApp ?: return@withLock
  val dao = app.database.securityIncidentDao()
  if (dao.findById(eventId)?.status?.substringAfterLast('|')?.let { it in terminalStates } == true) return@withLock
  // Receiver audit and scan cannot race: one owner inserts the record before assessment.
  runCatching {
   if (dao.findById(eventId) == null) {
    val source = InstallSourceVerifier(context).inspect(name)
    val privateText = EncryptedHashStore(context)
    dao.insert(SecurityIncidentEntity(eventId, System.currentTimeMillis(),
     if (updated) "PACKAGE_UPDATED" else "PACKAGE_INSTALL",
     installerPackage = (source.initiatingPackageName ?: source.installingPackageName)?.let {
      privateText.protectPrivateText(it, "incident-installer") },
     sourcePackage = privateText.protectPrivateText(name, "incident-source"),
     reason = privateText.protectPrivateText("Installer category: " + source.category.name, "incident-reason"),
     actionTaken = "POST_INSTALL_SCAN_QUEUED", status = source.category.name))
    if (source.needsReview && !updated && !TrustedAppStore(context).isTrusted(name)) {
     val label = runCatching {
      @Suppress("DEPRECATION")
      context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(name, 0)).toString()
     }.getOrDefault(name)
     InstallSourceNotifier.notify(context, label, source.sourceLabel, eventId)
    }
   }
  }.onFailure { Log.w("SafeMobileScan", "Install audit unavailable; scan continues", it) }
  try {
   // A package broadcast may cold-start the process before Application's async restore finishes.
   app.hashDatabaseManager.restoreActiveDatabase()
   Log.d("SafeMobileScan", "Post-install worker scanning package=$name event=$eventId")
   val scan = app.repository.scanInstalledPackage(name)
   if (scan == null) {
    Log.d("SafeMobileScan", "Final scan result: package=$name unavailable")
    val prior = dao.findById(eventId)
    if (prior != null) dao.updateAssessment(eventId,prior.sha256Hash,appendReason(context, prior.reason, "Package was not visible at scan time."),prior.actionTaken,prior.status + "|SCAN_UNAVAILABLE")
    return@withLock
   }
   if (scan.trustedByUser) return@withLock
   // Exact threats must alert even if a later optional heuristic/audit step fails.
   if (scan.verdict == ScanVerdict.THREAT) SecurityAlertNotifier.notifyMaliciousApp(context,name,eventId,scan.sha256)
   val static = StaticAnalyzer(context).analyze(name)
   val apk = static?.apkPath?.let(::File)
   val dex = apk?.let { DexPatternScanner().scan(it) }.orEmpty()
   val ml = static?.permissionFeatures?.let { PermissionModelScorer(context).probability(it) }
   val bloomScanner = BloomFilterScanner(context)
   // SHA-256, SHA-1 and MD5 were calculated in one streaming pass.
   val bloomChecks = listOfNotNull(scan.sha256, scan.sha1, scan.md5).map { bloomScanner.mightContainHash(it) }
   val bloom = when {
    bloomChecks.any { it == true } -> true
    bloomChecks.any { it == null } -> null
    else -> false
   }
   val integrity = IntegrityChecker(context).check()
   val reasons = linkedSetOf<String>()
   reasons.addAll(scan.reasons); static?.reasons?.let(reasons::addAll)
   dex.forEach { reasons += "DEX pattern indicator: " + it + " (review signal only)" }
   if (bloom == true) reasons += "Possible optional Bloom-filter match; verify with an exact local IOC before treating as malware."
   if (bloom == null) reasons += "No usable Bloom-filter asset bundled; exact local hash database remains active."
   if (ml == null) reasons += "Trained permission model unavailable; heuristic scoring used."
   if (integrity.isUntrusted) reasons.addAll(integrity.reasons)
   val exact = scan.verdict == ScanVerdict.THREAT
   val ruleRisk = scan.riskScore.coerceIn(0f,1f)
   val staticRisk = (static?.riskPoints ?: 0).coerceIn(0,100) / 100f
   val dexRisk = (dex.size / 4f).coerceIn(0f,1f)
   val bloomRisk = if (bloom == true) 0.6f else 0f
   val mlWeight = if (ml != null) 0.25f else 0f
   val subtotal = (ml ?: 0f)*mlWeight + ruleRisk*0.40f + staticRisk*0.15f + dexRisk*0.15f + bloomRisk*0.05f
   var score = if (exact) 1f else (subtotal / (mlWeight + 0.75f)).coerceIn(0f,1f)
   if (integrity.isUntrusted && score > 0f) {
    score = (score*1.5f).coerceAtMost(1f)
    reasons += "Integrity indicators increased triage score by 1.5x; not cryptographic attestation."
   }
   val verdict = ThreatVerdict(name,score,reasons.toList().take(40),exact)
   val previous = dao.findById(eventId)
   var action = previous?.actionTaken ?: "POST_INSTALL_SCAN_COMPLETED"
   // Consumer incident response always requires a user-confirmed Android uninstall.
   if (exact) action += "; CONFIRMED_LOCAL_HASH_MATCH"
   else if (score >= 0.45f) action += "; RISK_REVIEW"
   val reason = appendReason(context, previous?.reason, verdict.reasons.joinToString("; "))
   val status = when { exact -> "MALWARE_HASH_MATCH"; score >= 0.45f -> "RISK_REVIEW"; else -> "SCAN_COMPLETE" }
   if (previous != null) dao.updateAssessment(eventId,scan.sha256,reason,action.take(500),(previous.status + "|" + status).take(200))
   else dao.insert(SecurityIncidentEntity(eventId,System.currentTimeMillis(),"PACKAGE_INSTALL",sourcePackage=EncryptedHashStore(context).protectPrivateText(name, "incident-source"),sha256Hash=scan.sha256,
    reason=reason.ifBlank { "Post-install scan completed." },actionTaken=action.take(500),status=status))
   // Installed apps are not silently deleted or falsely described as quarantined; offer Android uninstall confirmation.
   Log.d("SafeMobileScan", "Final scan result: package=$name verdict=$status score=$score exact=$exact")
   if (!exact && score >= 0.45f) SecurityAlertNotifier.notifySuspiciousApp(context,name,eventId)

  } finally { InstallScanNotifications.finish(context, eventId) }
 }

 private fun appendReason(context: Context, prior: String?, detail: String): String {
  val store = EncryptedHashStore(context)
  val previous = prior?.let { runCatching { store.revealPrivateText(it, "incident-reason") }.getOrDefault("") }.orEmpty()
  return store.protectPrivateText((previous + "\n" + detail).trim().take(4000), "incident-reason")
 }
 private val terminalStates = setOf("MALWARE_HASH_MATCH", "RISK_REVIEW", "SCAN_COMPLETE", "SCAN_UNAVAILABLE")
}
