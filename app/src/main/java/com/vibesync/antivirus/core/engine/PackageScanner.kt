package com.vibesync.antivirus.core.engine
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import android.os.Build
import android.util.Log
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.UiText
import com.vibesync.antivirus.core.locale.SecurityText
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.google.common.hash.BloomFilter
import com.vibesync.antivirus.core.engine.hash.BloomFilterBuilder
import com.vibesync.antivirus.core.engine.hash.HashMatcher
import com.vibesync.antivirus.core.engine.hash.SignatureDatabaseParser
import com.vibesync.antivirus.core.engine.yara.YaraScanner as YaraXScanner
import com.vibesync.antivirus.core.engine.yara.YaraXRuleMatch
import com.vibesync.antivirus.core.engine.yara.YaraXScanResult
import com.vibesync.antivirus.core.engine.yara.YaraXScanState
import com.vibesync.antivirus.core.hashdb.HashDatabaseManager
import com.vibesync.antivirus.core.engine.DeepStaticAnalyzer
import com.vibesync.antivirus.engine.ensemble.ThreatEnsembleEvaluator
import com.vibesync.antivirus.core.heuristics.PermissionRiskAnalyzer
import com.vibesync.antivirus.core.security.IntegrityChecker
import com.vibesync.antivirus.core.security.ProtectedPackagePolicy
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.core.security.TrustedAppStore
import kotlin.math.roundToInt
import com.vibesync.antivirus.data.local.AppScanCache
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ThreatDao
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private const val APP_SCAN_CACHE_PROFILE_VERSION = 3
private const val MAX_SPLIT_APK_COUNT = 128
private const val GOOGLE_PLAY_SERVICES_PACKAGE = "com.google.android.gms"
private const val SAFE_SYSTEM_PACKAGE_LABEL = "Safe (System App)"

/**
 * Room/UI publication is an item boundary: a failed insert or observer callback
 * must not cancel sibling scans. Only cancellation of the parent scan is rethrown.
 */
internal suspend fun publishScanResultSafely(
 packageName: String,
 publish: suspend () -> Unit,
 logFailure: (String, Throwable) -> Unit = { pkg, error ->
  val userId = android.os.Process.myUid() / 100000
  Log.e("ScanDebug", "pkg_fail pkg=$pkg stage=publish userId=$userId", error)
 }
): Boolean {
 return try {
  publish()
  true
 } catch (cancelled: CancellationException) {
  if (!currentCoroutineContext().isActive) throw cancelled
  logFailure(packageName, cancelled)
  false
 } catch (error: Exception) {
  logFailure(packageName, error)
  false
 }
}

private val TRUSTED_CERTIFICATE_ANCHOR_PACKAGES = listOf(
 "com.google.android.gms",
 "com.android.vending"
)

class PackageScanner(
 private val context: Context,
 private val dao: ThreatDao,
 private val hashStore: EncryptedHashStore,
 private val calculator: HashCalculator = HashCalculator(),
 private val riskAnalyzer: PermissionRiskAnalyzer = PermissionRiskAnalyzer(),
 private val threatIntelligenceRepository: ThreatIntelligenceRepository? = null,
 private val hashDatabaseManager: HashDatabaseManager? = null
) {
 private val pm = context.packageManager
 private val TAG = "PackageScanner"
 private val eicarProbeBytes = 64 * 1024
 private val integrityChecker = IntegrityChecker(context)
 private val trustedAppStore = TrustedAppStore(context)
 private val deepStaticAnalyzer = DeepStaticAnalyzer()
 private val drebinFeatureExtractor = com.vibesync.antivirus.engine.ml.DrebinFeatureExtractor(context)
 private val tfliteInferenceEngine = com.vibesync.antivirus.engine.ml.TfliteInferenceEngine(context)
 private val yaraXScanner = YaraXScanner(context)

 private fun isProtectedPlatformPackage(
  packageName: String?,
  applicationInfo: ApplicationInfo?,
  diagnostics: PackageScanDiagnostics? = null
 ): Boolean {
  if (packageName == GOOGLE_PLAY_SERVICES_PACKAGE) return true
  val installedFlags = packageName?.let { name ->
   try {
    pm.getApplicationInfo(name, 0).flags
   } catch (error: Exception) {
    if (diagnostics != null) diagnostics.fail(name, "resolve", error)
    else {
     val userId = android.os.Process.myUid() / 100000
     Log.e("ScanDebug", "pkg_fail pkg=$name stage=resolve userId=$userId", error)
    }
    0
   }
  } ?: 0
  val flags = (applicationInfo?.flags ?: 0) or installedFlags
  return flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
 }

 private data class BundledHashSnapshot(
  val hashes: Set<String>,
  val bloomFilter: BloomFilter<String>
 )
 private data class PackageApkAssessment(
  val yaraResult: YaraXScanResult,
  val exactThreat: ScanResult? = null,
  val splitIssues: List<String> = emptyList(),
  val archiveFinding: ScanResult? = null,
  val archiveIssues: List<String> = emptyList()
 )
 private data class ArchiveAssessment(
  val finding: ScanResult?,
  val inspectedEntries: Int,
  val partialReason: String?
 ) {
  val isPartial: Boolean get() = !partialReason.isNullOrBlank()
 }

 private val signatureDatabaseParser = SignatureDatabaseParser()
 private val bloomFilterBuilder = BloomFilterBuilder()
 private val hashMatcher = HashMatcher()
 private val signatureDatabaseMutex = Mutex()
 private val appScanCacheProfileMutex = Mutex()

 @Volatile
 private var appScanCacheProfileReady = false

 @Volatile
 private var cachedBundledHashSnapshot: BundledHashSnapshot? = null

 /**
  * Loads the read-only bundled signatures once. EICAR is always inserted
  * independently of asset parsing so the fallback remains available if the
  * asset is absent, unreadable, or malformed.
  */
 private suspend fun loadBundledHashSnapshot(): BundledHashSnapshot {
  cachedBundledHashSnapshot?.let { return it }
  return signatureDatabaseMutex.withLock {
   cachedBundledHashSnapshot?.let { return@withLock it }
   val parsed = try {
    signatureDatabaseParser.parseDatabase(context, "signatures/mock_signatures.hsb")
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (_: Exception) {
    emptyList()
   }
   val hashes = (parsed + HashMatcher.EICAR_SHA256)
    .map { it.lowercase(java.util.Locale.ROOT) }
    .toSet()
   BundledHashSnapshot(
    hashes = hashes,
    bloomFilter = bloomFilterBuilder.buildBloomFilter(hashes.toList())
   ).also { cachedBundledHashSnapshot = it }
  }
 }

 private fun mergeYaraXFindings(report: RiskReport, scan: YaraXScanResult): RiskReport {
  val yaraFindings = scan.suspiciousMatches.map { match ->
   val severity = when (match.severity) {
    "critical", "high" -> RiskSeverity.HIGH
    "low" -> RiskSeverity.LOW
    else -> RiskSeverity.MEDIUM
   }
   RiskFinding(
    ruleId = "YARAX_" + match.ruleIdentifier,
    severity = severity,
    confidence = when (severity) {
     RiskSeverity.HIGH -> 70
     RiskSeverity.MEDIUM -> 55
     RiskSeverity.LOW -> 35
    },
    evidence = "YARA-X rule ${match.ruleIdentifier} matched ${match.componentName}. ${match.description}",
    details = (listOf(match.ruleIdentifier, match.namespace, match.componentName) +
     match.tags + match.matchedPatterns).take(64)
   )
  }
  val lowSeverityMatchCount = scan.suspiciousMatches.count { it.severity == "low" }
  val hasMediumOrHigherSeverity = scan.suspiciousMatches.any { it.severity != "low" }
  val addedScore = when {
   scan.suspiciousMatches.any { it.severity == "critical" || it.severity == "high" } -> 65
   hasMediumOrHigherSeverity || lowSeverityMatchCount >= 2 -> 45
   else -> 0
  }
  val notes = when (scan.state) {
   YaraXScanState.MATCHES -> listOf("YARA-X completed; ${scan.matches.size} rule match(es) observed.")
   YaraXScanState.NO_MATCH -> listOf("YARA-X completed; no bundled rule matched.")
   YaraXScanState.DISABLED -> listOf("YARA-X unavailable; this component was not evaluated by YARA-X.")
   YaraXScanState.NOT_SCANNED -> listOf("YARA-X did not complete: ${scan.reason.orEmpty()}")
  }
  val limitations = if (scan.isComplete) report.limitations else
   report.limitations + "YARA-X was not fully executed: ${scan.reason.orEmpty()}"
  return report.copy(
   findings = (report.findings + yaraFindings).distinctBy { it.ruleId + it.evidence },
   riskScore = maxOf(report.riskScore, addedScore),
   observations = (report.observations + notes).distinct(),
   limitations = limitations
  )
 }

 private fun yaraThreatResult(
  key: String,
  label: String,
  sha256: String,
  md5: String,
  match: YaraXRuleMatch,
  start: Long,
  packageName: String?,
  scanSessionId: String
 ): ScanResult {
  val name = match.malwareName ?: match.ruleIdentifier
  return ScanResult(
   key, label, sha256, md5, ScanVerdict.THREAT,
   listOf("YARA-X ${match.ruleIdentifier}: ${match.description}"), elapsed(start)
  ).copy(
   packageName = packageName,
   scanSessionId = scanSessionId,
   threatEventId = UUID.randomUUID().toString(),
   riskScore = 1f,
   detectionSource = DetectionSource.YARA,
   malwareName = name
  )
 }


 private fun rawYaraVerdict(yaraResult: YaraXScanResult?): ScanVerdict? = when {
  yaraResult == null -> null
  yaraResult.threatMatches.isNotEmpty() -> ScanVerdict.THREAT
  yaraResult.suspiciousMatches.isNotEmpty() -> ScanVerdict.SUSPICIOUS
  yaraResult.state == YaraXScanState.NO_MATCH -> ScanVerdict.NO_MATCH
  else -> null
 }

 private fun evaluateWithEnsemble(
  result: ScanResult,
  yaraResult: YaraXScanResult? = null,
  isSystemApp: Boolean = false
 ): ScanResult = ThreatEnsembleEvaluator.evaluate(
  result.copy(yaraVerdict = rawYaraVerdict(yaraResult)),
  isSystemApp = isSystemApp
 )

 private suspend fun runMachineLearning(apk: File): Float? {
  val features = drebinFeatureExtractor.extractFeaturesAsync(apk)
  // TFLite returns an advisory probability; the ensemble alone assigns the final verdict.
  return tfliteInferenceEngine.runInference(features)
 }

 fun installedAppInventory(): List<InstalledAppItem> {
  val userId = android.os.Process.myUid() / 100000
  val packages = try {
   @Suppress("DEPRECATION")
   pm.getInstalledPackages(0)
  } catch (error: Exception) {
   Log.e(TAG, "PackageManager could not enumerate the installed-app inventory.", error)
   return emptyList()
  }
  return packages.asSequence().filter { info ->
   val appInfo = info.applicationInfo ?: run {
    Log.i("ScanDebug", "pkg_skipped pkg=${info.packageName} reason=inventory_application_info_missing userId=$userId source=all_apps_inventory")
    return@filter false
   }
      val flags = appInfo.flags
   val included = ProtectedPackagePolicy.isUserInstalled(flags, info.packageName, context.packageName)
   if (!included) {
    val reason = when {
     info.packageName == context.packageName -> "inventory_own_package"
     TrustedPackageWhitelist.hasProtectedNamespace(info.packageName) -> "inventory_protected_namespace"
     TrustedPackageWhitelist.hasSystemFlags(flags) -> "inventory_system_flags"
     else -> "inventory_not_user_installed"
    }
    Log.i("ScanDebug", "pkg_skipped pkg=${info.packageName} reason=$reason flags=$flags userId=$userId source=user_apps_inventory")
   }
   included
  }.mapNotNull { info ->
   val appInfo = info.applicationInfo ?: run {
    Log.i("ScanDebug", "pkg_skipped pkg=${info.packageName} reason=inventory_application_info_missing userId=$userId source=all_apps_inventory")
    return@mapNotNull null
   }
   val label = try {
    appInfo.loadLabel(pm)?.toString().orEmpty().ifBlank { info.packageName }
   } catch (error: Exception) {
    Log.e("ScanDebug", "pkg_fail pkg=${info.packageName} stage=label userId=$userId", error)
    info.packageName
   }
   val apkSize = try {
    installedApkBytes(appInfo) ?: 0L
   } catch (error: Exception) {
    Log.e("ScanDebug", "pkg_fail pkg=${info.packageName} stage=resolve userId=$userId", error)
    0L
   }
   val isSystem = appInfo.flags and
    (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
   InstalledAppItem(
    info.packageName, label,
    InstalledAppItem.INVENTORY_ONLY,
    apkSize, isSystem
   )
  }.distinctBy { it.packageName }.sortedBy { it.appLabel.lowercase(java.util.Locale.getDefault()) }.toList()
 }
 suspend fun scanInstalledApps(progress: suspend (processed: Int, total: Int) -> Unit = { _, _ -> }): List<ScanResult> =
   scanInstalledAppsForSession(UUID.randomUUID().toString(), progress)

 suspend fun scanInstalledAppsForSession(
  scanSessionId: String, progress: suspend (processed: Int, total: Int) -> Unit = { _, _ -> }
 ): List<ScanResult> = scanInstalledAppsForSession(scanSessionId, emptySet(), {}, progress)

 suspend fun scanInstalledAppsForSession(
  scanSessionId: String, completedPackageNames: Set<String>,
  onItemCompleted: suspend (ScanResult) -> Unit,
  progress: suspend (processed: Int, total: Int) -> Unit
 ): List<ScanResult> = supervisorScope {
  val diagnostics = PackageScanDiagnostics()
  var enumeratedTotal = 0

  // Apply the third-party user-app eligibility policy before queueing installed packages.
  // Excluded system, OEM, Google and scanner packages never reach the scan worker.
  val all = withContext(Dispatchers.IO) {
   val packages = try {
    @Suppress("DEPRECATION")
    pm.getInstalledPackages(0)
   } catch (error: Exception) {
    Log.e(TAG, "PackageManager could not enumerate installed packages.", error)
    emptyList()
   }
   enumeratedTotal = packages.size
   packages.mapNotNull { info ->
    val packageName = info.packageName
    try {
     val app = info.applicationInfo ?: run {
      diagnostics.skip(packageName, "application_info_missing")
      return@mapNotNull null
     }
           if (!ProtectedPackagePolicy.isUserInstalled(app.flags, packageName, context.packageName)) {
       val reason = when {
        packageName == context.packageName -> "scanner_own_package"
        TrustedPackageWhitelist.hasProtectedNamespace(packageName) -> "protected_google_android_or_oem_namespace"
        TrustedPackageWhitelist.hasSystemFlags(app.flags) -> "system_or_updated_system_app"
        else -> "not_user_installed"
       }
       diagnostics.skip(packageName, reason)
       return@mapNotNull null
      }
      diagnostics.queue(packageName, "user_installed_third_party_app", app.flags)
      packageName
    } catch (error: Exception) {
     diagnostics.fail(packageName, "resolve", error)
     null
    }
   }.distinct().sorted()
  }
  diagnostics.setTotal(enumeratedTotal)
  try { dao.updateScanSessionInventory(scanSessionId, enumeratedTotal, all.size, diagnostics.skipped) }
  catch (error: Exception) { diagnostics.fail("*", "inventory_persist", error) }
  Log.i("ScanDebug", "pkg_inventory enumerated=$enumeratedTotal eligible=${all.size} excluded=${diagnostics.skipped} userId=${diagnostics.userId}")

  val completed = all.count { it in completedPackageNames }
  // Resumed rows already exist in the Room session; count them as published,
  // but keep them out of this pass's per-package work queue.
  diagnostics.markPublished(completed)
  diagnostics.markResumedCompleted(completed)
  all.filter { it in completedPackageNames }.forEach { packageName ->
   diagnostics.resume(packageName)
  }
  val pending = all.filterNot { it in completedPackageNames }
  val semaphore = Semaphore(3)
  val count = AtomicInteger(0)
  val mutex = Mutex()
  try {
   progress(completed, all.size)
  } catch (cancelled: CancellationException) {
   if (!currentCoroutineContext().isActive) throw cancelled
   Log.e("ScanDebug", "Initial scan progress callback cancelled.", cancelled)
  } catch (error: Exception) {
   Log.e("ScanDebug", "Could not publish initial scan progress.", error)
  }
  val results = try {
   pending.map { packageName ->
    Log.d("ScanDebug", "Starting scan for package: $packageName")
    async(Dispatchers.IO) {
     var stage = "resolve"
     diagnostics.iconNotApplicable(packageName)
     val scanResult = try {
      semaphore.withPermit {
       currentCoroutineContext().ensureActive()
       val start = System.nanoTime()
       try {
        val packageInfo = loadPackageInfoForScan(packageName, diagnostics)
        logPackageMetadata(packageInfo, diagnostics)
        scanPackage(packageInfo, scanSessionId, diagnostics) { nextStage ->
         stage = nextStage
         diagnostics.stage(packageName, nextStage, "started")
        }
       } catch (cancelled: CancellationException) {
        if (!currentCoroutineContext().isActive) throw cancelled
        diagnostics.fail(packageName, stage, cancelled)
        Log.e("ScanDebug", "Package scan cancelled locally: $packageName", cancelled)
        result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
         listOf(context.getString(R.string.file_could_not_read)), start)
         .copy(packageName = packageName, scanSessionId = scanSessionId)
       } catch (error: Exception) {
        diagnostics.fail(packageName, stage, error)
        Log.e("ScanDebug", "Package scan failed: $packageName", error)
        val failed = result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
         listOf(context.getString(R.string.file_could_not_read)), start)
         .copy(packageName = packageName, scanSessionId = scanSessionId)
        auditSafely(failed, start, scanSessionId, diagnostics)
        failed
       }
      }
     } catch (cancelled: CancellationException) {
      if (!currentCoroutineContext().isActive) throw cancelled
      diagnostics.fail(packageName, stage, cancelled)
      Log.e("ScanDebug", "Scan task cancelled before package analysis: $packageName", cancelled)
      result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
       listOf(context.getString(R.string.file_could_not_read)), System.nanoTime())
       .copy(packageName = packageName, scanSessionId = scanSessionId)
     } catch (error: Exception) {
      diagnostics.fail(packageName, stage, error)
      Log.e("ScanDebug", "Scan task failed before package analysis: $packageName", error)
      result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
       listOf(context.getString(R.string.file_could_not_read)), System.nanoTime())
       .copy(packageName = packageName, scanSessionId = scanSessionId)
     }
     val didPublish = publishScanResultSafely(packageName, { onItemCompleted(scanResult) }) { pkg, error ->
      val failureStage = (error as? ScanPublishStageException)?.stage ?: "publish"
      diagnostics.fail(pkg, failureStage, error.cause ?: error)
     }
     if (didPublish) {
      diagnostics.markPublished()
      diagnostics.recordResult(scanResult)
     }
     try {
      mutex.withLock { progress(completed + count.incrementAndGet(), all.size) }
     } catch (cancelled: CancellationException) {
      if (!currentCoroutineContext().isActive) throw cancelled
      Log.e("ScanDebug", "Scan progress callback cancelled for package: $packageName", cancelled)
     } catch (error: Exception) {
      Log.e("ScanDebug", "Could not update scan progress for package: $packageName", error)
     }
     scanResult
    }
   }.awaitAll()
  } catch (cancelled: CancellationException) {
   if (!currentCoroutineContext().isActive) throw cancelled
   pending.forEach { packageName -> diagnostics.fail(packageName, "publish", cancelled) }
   Log.e("ScanDebug", "A package task was cancelled independently; retaining per-package outcomes.", cancelled)
   pending.map { packageName ->
    result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
     listOf(context.getString(R.string.file_could_not_read)), System.nanoTime())
     .copy(packageName = packageName, scanSessionId = scanSessionId)
   }
  } catch (error: Exception) {
   pending.forEach { packageName -> diagnostics.fail(packageName, "publish", error) }
   Log.e("ScanDebug", "Installed-app scan queue failed while awaiting package tasks.", error)
   pending.map { packageName ->
    result(packageName, packageName, null, null, ScanVerdict.NOT_SCANNED,
     listOf(context.getString(R.string.file_could_not_read)), System.nanoTime())
     .copy(packageName = packageName, scanSessionId = scanSessionId)
   }
  }
  diagnostics.logSummary()
  ScanResultOrdering.sort(results)
 }
 suspend fun scanInstalledPackage(name: String, scanSessionId: String = UUID.randomUUID().toString()): ScanResult? {
  if (name == context.packageName) return null
  val info = try {
   loadPackageInfoForScan(name)
  } catch (_: PackageManager.NameNotFoundException) {
   return null
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   val start = System.nanoTime()
   Log.e(TAG, "Skipping installed package because PackageManager metadata retrieval failed: " + name, error)
   val failed = result(
    name, name, null, null, ScanVerdict.NOT_SCANNED,
    listOf(context.getString(R.string.package_metadata_missing)), start
   ).copy(packageName = name, scanSessionId = scanSessionId)
   auditSafely(failed, start, scanSessionId)
   return failed
  }
  val appInfo = info.applicationInfo ?: return null
  // Direct package requests use the same strict filter as inventory and periodic scans.
  if (!ProtectedPackagePolicy.isUserInstalled(appInfo.flags, info.packageName, context.packageName)) {
   val reason = when {
    TrustedPackageWhitelist.hasProtectedNamespace(info.packageName) -> "protected_google_android_or_oem_namespace"
    TrustedPackageWhitelist.hasSystemFlags(appInfo.flags) -> "system_or_updated_system_app"
    else -> "not_user_installed"
   }
   Log.i("ScanDebug", "pkg_skipped pkg=${info.packageName} reason=$reason source=direct_installed_scan")
   return null
  }
  if (trustedAppStore.isTrusted(name)) return trustedResult(name, scanSessionId, System.nanoTime())
  return scanPackage(info, scanSessionId)
 }
 suspend fun scanFile(
  file: File,
  persistAllAudit: Boolean = true,
  inspectEmbeddedArchives: Boolean = true
 ): ScanResult {
  val start = System.nanoTime()
  val scanSessionId = UUID.randomUUID().toString()
  if (!file.isFile || !file.canRead()) {
   val failed = result(file.name, file.name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_not_readable)), start)
   auditSafely(failed, start, scanSessionId)
   return failed.copy(sourceLocalPath = file.absolutePath, scanSessionId = scanSessionId)
  }
  return try {
   // Ask PackageManager for an APK manifest regardless of the filename extension. A
   // renamed APK must still resolve its signed package identity before any scanning.
   val archiveFlags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
    PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or
    PackageManager.GET_PROVIDERS or signingFlags()
   val apkPackageInfo = try {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
     pm.getPackageArchiveInfo(
      file.absolutePath,
      PackageManager.PackageInfoFlags.of(archiveFlags.toLong())
     )
    } else {
     @Suppress("DEPRECATION")
     pm.getPackageArchiveInfo(file.absolutePath, archiveFlags)
    }
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (_: Exception) {
    null
   }
   // Keep malformed .apk files on the APK diagnostic path, even when PackageManager
   // cannot parse their manifest. Non-APK files with unrelated extensions stay file-only.
   val isApk = apkPackageInfo != null || file.extension.equals("apk", ignoreCase = true)
   apkPackageInfo?.applicationInfo?.apply {
    sourceDir = file.absolutePath
    publicSourceDir = file.absolutePath
   }
   val identity = apkPackageInfo?.packageName
   val protectedPlatformApk = isProtectedPlatformPackage(identity, apkPackageInfo?.applicationInfo)
   if (identity != null && trustedAppStore.isTrusted(identity)) {
    return trustedResult(identity, scanSessionId, start).copy(sourceLocalPath = file.absolutePath)
   }
   val hash = withContext(Dispatchers.Default) { calculator.calculate(file) }
   // Skip ZIP/DEX, bundled YARA and ML when any exact local threat hash matches.
  // The conclusive signature verdict is still recorded in the normal audit.
  val exactThreat = findExactHashThreat(file.name, file.name,
   hash.sha256, hash.md5, hash.sha1, hash.bytesRead)
  if (exactThreat != null) {
   // Exact hash matches remain an immediate short-circuit: no YARA or ML work runs.
   val evaluated = evaluateWithEnsemble(exactThreat)
   audit(evaluated, start, scanSessionId)
   return evaluated.copy(durationMs = elapsed(start),
    sourceLocalPath = file.absolutePath, scanSessionId = scanSessionId)
  }

  val namedArchive = file.extension.equals("zip", ignoreCase = true) ||
   file.extension.equals("jar", ignoreCase = true)
  if (!isApk && (hasZipSignature(file) || namedArchive)) {
   val archive = scanArchiveContents(
    archive = file,
    scanSessionId = scanSessionId,
    includeAllLeafEntries = true
   )
   val archiveResult = archive.finding ?: evaluateUnmatched(
    file.name, file.name, hash.sha256, hash.md5, emptyList(), 0,
    sha1 = hash.sha1
   )
   var covered = archiveResult.copy(
    durationMs = elapsed(start),
    sourceLocalPath = file.absolutePath,
    scanSessionId = scanSessionId,
    analysisStages = (archiveResult.analysisStages + listOf("HASH", "ARCHIVE_INSPECTED")).distinct()
   )
   if (archive.isPartial) {
    covered = ScanCoveragePolicy.applyPartialCoverage(
     covered, "ARCHIVE_INCOMPLETE",
     archive.partialReason ?: "One or more archive entries could not be completely inspected."
    )
   }
   if (persistAllAudit || covered.verdict in setOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS, ScanVerdict.NOT_SCANNED)) {
    audit(covered, start, scanSessionId)
   }
   return covered
  }

  val yaraXResult = if (isApk) {
   withContext(Dispatchers.Default) { yaraXScanner.scanApk(file, allowManifestOnly = true) }
  } else null
  val yaraThreat = yaraXResult?.threatMatches?.firstOrNull()
  if (yaraThreat != null) {
   val detected = evaluateWithEnsemble(
    yaraThreatResult(
     file.name, file.name, hash.sha256, hash.md5,
     yaraThreat, start, null, scanSessionId
    ),
    yaraXResult
   )
   audit(detected, start, scanSessionId)
   return detected.copy(
    durationMs = elapsed(start),
    sourceLocalPath = file.absolutePath,
    scanSessionId = scanSessionId
   )
  }

  val embeddedArchive = if (isApk && inspectEmbeddedArchives) scanArchiveContents(
   archive = file,
   scanSessionId = scanSessionId,
   includeAllLeafEntries = false,
   ownerPackageName = identity
  ) else null
  embeddedArchive?.let { archiveCoverage ->
   archiveCoverage.finding?.takeIf { it.verdict == ScanVerdict.THREAT }?.let { archiveFinding ->
    var detected = archiveFinding.copy(
     packageOrPath = identity ?: file.name,
     displayName = identity ?: file.name,
     packageName = identity ?: archiveFinding.packageName,
     scanSessionId = scanSessionId,
     apkSizeBytes = hash.bytesRead,
     sourceLocalPath = file.absolutePath,
     durationMs = elapsed(start),
     analysisStages = (listOf("HASH", "YARA") + archiveFinding.analysisStages + "ARCHIVE_INSPECTED").distinct()
    )
    if (archiveCoverage.isPartial) {
     detected = ScanCoveragePolicy.applyPartialCoverage(
      detected, "ARCHIVE_INCOMPLETE",
      archiveCoverage.partialReason ?: "An embedded ZIP/JAR entry could not be completely inspected."
     )
    }
    audit(detected, start, scanSessionId)
    return detected
   }
  }

   // Do not execute the Drebin model for installed system apps or Google Play Services.
   val mlProbability = if (isApk && !protectedPlatformApk) {
    runMachineLearning(file)
   } else null
   val staticReport = if (isApk) {
    // Reuse the early PackageManager manifest/permission parse instead of parsing the APK twice.
    val baseReport = deepStaticAnalyzer.analyze(
     apkPackageInfo,
     file,
     apkPackageInfo?.let { isDebugSigned(it) } == true
    )
    val mergedReport = yaraXResult?.let { mergeYaraXFindings(baseReport, it) } ?: baseReport
    mergedReport.copy(mlProbability = mlProbability)
   } else null
   val staticReasons = staticReport?.findings.orEmpty().map { "[${it.ruleId}] ${it.evidence} (confidence ${it.confidence}%)" }
   val staticScore = staticReport?.riskScore ?: 0
   val assessed = evaluateUnmatched(file.name, file.name, hash.sha256, hash.md5, staticReasons, staticScore, sha1 = hash.sha1, report = staticReport)
    .copy(riskReport = staticReport, mlProbability = staticReport?.mlProbability)
   val firstSuspiciousYara = yaraXResult?.suspiciousMatches?.firstOrNull()
   var output = assessed
   if (firstSuspiciousYara != null) {
    output = output.copy(
     malwareName = firstSuspiciousYara.malwareName ?: firstSuspiciousYara.ruleIdentifier
    )
   }
   output = evaluateWithEnsemble(output, yaraXResult, isSystemApp = protectedPlatformApk)
   output = mergeArchiveSuspicion(output, embeddedArchive?.finding)
   output = ScanCoveragePolicy.applyYaraCoverage(output, yaraXResult?.state, yaraXResult?.reason)
   if (embeddedArchive?.isPartial == true) {
    output = ScanCoveragePolicy.applyPartialCoverage(
     output, "ARCHIVE_INCOMPLETE",
     embeddedArchive.partialReason ?: "An embedded ZIP/JAR entry could not be completely inspected."
    )
   } else if ((embeddedArchive?.inspectedEntries ?: 0) > 0) {
    output = output.copy(analysisStages = (output.analysisStages + "ARCHIVE_INSPECTED").distinct())
   }
   if (!isApk) {
    val prefix = file.inputStream().buffered().use(::readBoundedPrefix)
    output = ThreatEnsembleEvaluator.evaluateTextPayload(output, prefix)
   }
   if (persistAllAudit || output.verdict == ScanVerdict.THREAT || output.verdict == ScanVerdict.SUSPICIOUS || output.verdict == ScanVerdict.NOT_SCANNED) audit(output, start, scanSessionId)
   output.copy(durationMs = elapsed(start), sourceLocalPath = file.absolutePath, scanSessionId = scanSessionId)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (_: Exception) {
   val failed = result(file.name, file.name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_could_not_read)), start)
   auditSafely(failed, start, scanSessionId)
   failed.copy(sourceLocalPath = file.absolutePath, scanSessionId = scanSessionId)
  }
 }
 suspend fun scanStream(
  label: String,
  stream: java.io.InputStream,
  scanSessionId: String = UUID.randomUUID().toString(),
  persistAudit: Boolean = true
 ): ScanResult {
  val start = System.nanoTime()
  return try {
   val inputStream = stream.buffered()
   inputStream.mark(2)
   val zipHeader = inputStream.read() == 0x50 && inputStream.read() == 0x4b
   inputStream.reset()
   val archiveLabel = label.substringBefore('?')
   val isNamedApk = archiveLabel.endsWith(".apk", ignoreCase = true)
   val isNamedArchive = archiveLabel.endsWith(".zip", ignoreCase = true) ||
    archiveLabel.endsWith(".jar", ignoreCase = true)
   if (zipHeader || isNamedApk || isNamedArchive) {
    // A content URI does not expose package identity. Stage APK bytes in app-private
    // cache so PackageManager can read the manifest before any detection engine.
    // Preserve archive kind: an ordinary ZIP must not be renamed and routed as an APK.
    val staged = File.createTempFile(
     if (isNamedApk) "scan-apk-" else "scan-zip-",
     if (isNamedApk) ".apk" else ".zip",
     context.cacheDir
    )
    try {
     inputStream.use { input -> staged.outputStream().use { output ->
      val buffer = ByteArray(64 * 1024)
      var total = 0L
      while (true) {
       currentCoroutineContext().ensureActive()
       val read = input.read(buffer)
       if (read < 0) break
       total += read
       require(total <= 512L * 1024 * 1024) { "Archive staging limit exceeded" }
       output.write(buffer, 0, read)
      }
     } }
     return scanFile(staged, persistAudit).copy(packageOrPath = label, displayName = label,
      sourceLocalPath = null, scanSessionId = scanSessionId)
    } finally { staged.delete() }
   }
   val eicarProbe = if (zipHeader || label.substringBefore('?').endsWith(".apk", ignoreCase = true)) {
    null
   } else {
    inputStream.mark(eicarProbeBytes)
    readBoundedPrefix(inputStream).also { inputStream.reset() }
   }
   val hash = inputStream.use { withContext(Dispatchers.Default) { calculator.calculate(it) } }
   var output = evaluate(label, label, hash.sha256, hash.md5, emptyList(), 0, sha1 = hash.sha1, fileSize = hash.bytesRead)
   if (eicarProbe != null) output = ThreatEnsembleEvaluator.evaluateTextPayload(output, eicarProbe)
   if (persistAudit || output.verdict == ScanVerdict.THREAT ||
       output.verdict == ScanVerdict.SUSPICIOUS || output.verdict == ScanVerdict.NOT_SCANNED) {
    audit(output, start, scanSessionId)
   }
   output.copy(durationMs = elapsed(start), scanSessionId = scanSessionId)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (_: Exception) {
   result(label, label, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_stream_failed)), start).copy(scanSessionId = scanSessionId).also { auditSafely(it, start, scanSessionId) }
  } finally { runCatching { stream.close() } }
 }
 private suspend fun scanPackage(
  info: PackageInfo,
  scanSessionId: String,
  diagnostics: PackageScanDiagnostics? = null,
  onStageChange: (String) -> Unit = {}
 ): ScanResult {
  var activeStage = "resolve"
  val stageCallback: (String) -> Unit = { nextStage ->
   activeStage = nextStage
   onStageChange(nextStage)
  }
  stageCallback("resolve")
  val start = System.nanoTime()
  val appInfo = info.applicationInfo
  val fileSize = installedApkBytes(appInfo)

  if (trustedAppStore.isTrusted(info.packageName)) {
   return trustedResult(info.packageName, scanSessionId, start).copy(
    apkSizeBytes = fileSize, scanSource = ScanSource.USER_TRUSTED,
    analysisStages = listOf("USER_TRUSTED", "VERDICT")
   )
  }

  val flags = appInfo?.flags ?: 0
  val isSystemApp = flags and ApplicationInfo.FLAG_SYSTEM != 0
  val isUpdatedSystemApp = flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
  val cacheProfileReady = ensureCurrentAppScanCacheProfile()
  val cached = if (!cacheProfileReady) null else try {
   dao.findAppScanCache(info.packageName)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   diagnostics?.fail(info.packageName, "resolve", error)
   Log.w(TAG, "Could not read the installed-app scan cache.", error)
   null
  }

  // Defensive direct-scan guard; bulk enumeration excludes all other platform/OEM apps.
  if (isSystemApp || isUpdatedSystemApp) {
   return safePlatformPackageResult(
    info, scanSessionId, start, fileSize, SAFE_SYSTEM_PACKAGE_LABEL,
    diagnostics, stageCallback, ScanSource.FRESH,
    listOf("SYSTEM_POLICY", "VERDICT")
   )
  }

  if (cached?.verdict == ScanVerdict.NOT_SCANNED.name) {
   try {
    dao.deleteAppScanCache(info.packageName)
    Log.i("ScanDebug", "pkg_cache_bypass pkg=${info.packageName} reason=legacy_not_scanned_cache_removed userId=${diagnostics?.userId ?: (android.os.Process.myUid() / 100000)}")
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    diagnostics?.fail(info.packageName, "cache_delete", error)
   }
  }

  if (fileSize != null && cached != null &&
   cached.lastUpdateTime == info.lastUpdateTime && cached.fileSize == fileSize
  ) {
   val cachedVerdict = try {
    ScanVerdict.valueOf(cached.verdict)
   } catch (error: Exception) {
    diagnostics?.fail(info.packageName, "resolve", error)
    null
   }
   if (cachedVerdict != null && AppScanCachePolicy.canReuse(cachedVerdict)) {
    Log.i("ScanDebug", "pkg_cache_hit pkg=${info.packageName} verdict=$cachedVerdict reason=unchanged_apk userId=${diagnostics?.userId ?: (android.os.Process.myUid() / 100000)}")
    val label = loadPackageLabelOrFallback(info, diagnostics, stageCallback)
    val cachedResult = ScanResult(
     packageOrPath = info.packageName, displayName = label,
     sha256 = cached.sha256.takeIf { it.isNotBlank() }, md5 = null,
     verdict = cachedVerdict, reasons = cached.threatName?.let(::listOf).orEmpty(),
     durationMs = elapsed(start)
    ).copy(
     packageName = info.packageName, scanSessionId = scanSessionId,
     malwareName = cached.threatName, apkSizeBytes = fileSize,
     scanSource = ScanSource.CACHE_HIT, analysisStages = listOf("CACHE_HIT")
    )
    auditSafely(cachedResult, start, scanSessionId, diagnostics)
    return cachedResult
   }
  }

  val scanned = try {
   scanPackageUncached(info, scanSessionId, fileSize, diagnostics, stageCallback)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   val failedStage = (error as? ScanPublishStageException)?.stage ?: activeStage
   diagnostics?.fail(info.packageName, failedStage, error.cause ?: error)
   Log.w(TAG, "Installed-app scan failed; retaining an explicit retryable result.", error)
   val label = loadPackageLabelOrFallback(info, diagnostics, onStageChange)
   result(info.packageName, label, null, null, ScanVerdict.NOT_SCANNED,
    listOf(context.getString(R.string.file_could_not_read)), start).copy(
     packageName = info.packageName, scanSessionId = scanSessionId,
     apkSizeBytes = fileSize, scanSource = ScanSource.FRESH,
     analysisStages = listOf("${failedStage.uppercase()}_FAILED", "VERDICT_PENDING")
    ).also { auditSafely(it, start, scanSessionId, diagnostics) }
  }

  val finalResult = scanned.copy(apkSizeBytes = fileSize, scanSource = ScanSource.FRESH)
  if (cacheProfileReady && fileSize != null && AppScanCachePolicy.shouldPersist(finalResult)) {
   try {
    dao.upsertAppScanCache(AppScanCache(
     packageName = info.packageName, lastUpdateTime = info.lastUpdateTime,
     fileSize = fileSize, sha256 = finalResult.sha256.orEmpty(),
     verdict = finalResult.verdict.name, threatName = finalResult.malwareName
    ))
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    diagnostics?.fail(info.packageName, "room_insert", error)
    Log.w(TAG, "Could not update installed-app cache; scan result remains valid.", error)
   }
  } else if (!cacheProfileReady) {
   Log.w("ScanDebug", "pkg_cache_bypass pkg=${info.packageName} reason=cache_profile_invalidation_unavailable")
  } else if (finalResult.verdict == ScanVerdict.NOT_SCANNED) {
   Log.i("ScanDebug", "pkg_retry_required pkg=${info.packageName} reason=incomplete_analysis_not_cached userId=${diagnostics?.userId ?: (android.os.Process.myUid() / 100000)}")
  }
  return finalResult
 }

 private suspend fun safePlatformPackageResult(
  info: PackageInfo,
  scanSessionId: String,
  start: Long,
  fileSize: Long?,
  safeLabel: String,
  diagnostics: PackageScanDiagnostics? = null,
  onStageChange: (String) -> Unit = {},
  scanSource: ScanSource = ScanSource.FRESH,
  analysisStages: List<String> = listOf("PLATFORM_POLICY", "VERDICT")
 ): ScanResult {
  val displayName = loadPackageLabelOrFallback(info, diagnostics, onStageChange)
  val safeResult = ScanResult(
   packageOrPath = info.packageName,
   displayName = displayName,
   sha256 = null,
   md5 = null,
   verdict = ScanVerdict.NO_MATCH,
   reasons = listOf(safeLabel),
   durationMs = elapsed(start)
  ).copy(
   packageName = info.packageName, scanSessionId = scanSessionId,
   apkSizeBytes = fileSize, scanSource = scanSource, analysisStages = analysisStages
  )

  // No digest is computed for an early-exit package; the empty value is deliberately non-hash data.
  if (fileSize != null) {
   try {
    dao.upsertAppScanCache(
     AppScanCache(
      packageName = info.packageName,
      lastUpdateTime = info.lastUpdateTime,
      fileSize = fileSize,
      sha256 = "",
      verdict = ScanVerdict.NO_MATCH.name,
      threatName = safeLabel
     )
    )
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    diagnostics?.fail(info.packageName, "room_insert", error)
    Log.w(TAG, "Could not cache the safe platform package result.", error)
   }
  }
  auditSafely(safeResult, start, scanSessionId, diagnostics)
  return safeResult
 }

 private suspend fun scanPackageUncached(
  info: PackageInfo,
  scanSessionId: String,
  fileSize: Long?,
  diagnostics: PackageScanDiagnostics? = null,
  onStageChange: (String) -> Unit = {}
 ): ScanResult {
  val start = System.nanoTime()
  val appInfo = info.applicationInfo ?: run {
   diagnostics?.fail(info.packageName, "resolve", IllegalStateException("PackageInfo.applicationInfo is null"))
   val failed = result(info.packageName, info.packageName, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.package_metadata_missing)), start).copy(
    packageName = info.packageName, scanSessionId = scanSessionId,
    analysisStages = listOf("RESOLVE_FAILED", "VERDICT_PENDING")
   )
   auditSafely(failed, start, scanSessionId, diagnostics)
   return failed
  }
  val completedStages = mutableListOf<String>()
  onStageChange("label")
  val label = try {
   appInfo.loadLabel(pm).toString()
  } catch (error: Exception) {
   throw ScanPublishStageException("label", error)
  }
  val permissions = info.requestedPermissions?.toSet().orEmpty()
  val accessibility = info.services.orEmpty().any { it.permission == PermissionRiskAnalyzer.BIND_ACCESSIBILITY }
  val risk = riskAnalyzer.assess(permissions, accessibility)
  val deviceIntegrity = integrityChecker.check()
  val adjustedRiskScore = (risk.score * deviceIntegrity.riskMultiplier).roundToInt().coerceIn(0, 100)
  val reasons = risk.reasonResourceIds.map(context::getString).toMutableList()
  if (deviceIntegrity.isUntrusted) reasons += deviceIntegrity.reasons
  val debugSigned = isDebugSigned(info, diagnostics)
  if (debugSigned) reasons += context.getString(R.string.debug_certificate)
  val apk = appInfo.sourceDir?.let(::File)
  if (apk == null || !apk.isFile || !apk.canRead()) {
   reasons += context.getString(R.string.apk_unreadable)
   val unreadableVerdict = if (adjustedRiskScore >= 45) ScanVerdict.SUSPICIOUS else ScanVerdict.NOT_SCANNED
   if (unreadableVerdict == ScanVerdict.NOT_SCANNED) {
    diagnostics?.skip(info.packageName, "apk_source_missing_or_unreadable")
   }
   val failed = result(info.packageName, label, null, null, unreadableVerdict, reasons, start).copy(
    packageName = info.packageName, scanSessionId = scanSessionId,
    detectionSource = if (adjustedRiskScore >= 45) DetectionSource.HEURISTIC else DetectionSource.NONE,
    analysisStages = listOf("RESOLVE_FAILED", "VERDICT_PENDING")
   )
   auditSafely(failed, start, scanSessionId, diagnostics)
   return failed
  }
  onStageChange("hash")
  val hashes = try {
   withContext(Dispatchers.Default) { calculator.calculate(apk) }
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   diagnostics?.fail(info.packageName, "hash", error)
   null
  } ?: run {
    val failed = result(info.packageName, label, null, null, ScanVerdict.NOT_SCANNED, reasons + context.getString(R.string.file_could_not_read), start).copy(packageName = info.packageName, scanSessionId = scanSessionId)
    auditSafely(failed, start, scanSessionId, diagnostics)
    return failed.copy(analysisStages = listOf("HASH_FAILED", "VERDICT_PENDING"))
   }
  completedStages += "HASH"
  diagnostics?.stage(info.packageName, "hash", "completed")
  onStageChange("resolve")
  // The hash engine must run before expensive DEX/YARA/ML work. Preserve the
  // existing signed DB, local DB and optional feed ordering and threat evidence.
  val exactThreat = findExactHashThreat(info.packageName, label,
   hashes.sha256, hashes.md5, hashes.sha1, hashes.bytesRead)
  if (exactThreat != null) {
   // Exact hash matches remain an immediate short-circuit: no YARA or ML work runs.
   val evaluated = evaluateWithEnsemble(exactThreat)
   audit(evaluated, start, scanSessionId, diagnostics)
   onStageChange("verdict")
   diagnostics?.stage(info.packageName, "verdict", "completed")
   return evaluated.copy(
    durationMs = elapsed(start), packageName = info.packageName, scanSessionId = scanSessionId,
    analysisStages = completedStages + "VERDICT"
   )
  }

  onStageChange("yara")
  val apkAssessment = scanPackageApks(
   baseApk = apk,
   splitPaths = appInfo.splitSourceDirs,
   packageName = info.packageName,
   displayName = label,
   scanSessionId = scanSessionId,
   apkBytes = fileSize,
   diagnostics = diagnostics
  )
  apkAssessment.exactThreat?.let { splitThreat ->
   val detected = splitThreat.copy(
    durationMs = elapsed(start),
    packageName = info.packageName,
    scanSessionId = scanSessionId,
    analysisStages = completedStages + listOf("HASH", "SPLIT_HASH", "VERDICT")
   )
   audit(detected, start, scanSessionId, diagnostics)
   onStageChange("verdict")
   diagnostics?.stage(info.packageName, "verdict", "completed")
   return detected
  }
  apkAssessment.archiveFinding?.takeIf { it.verdict == ScanVerdict.THREAT }?.let { splitArchiveThreat ->
   val detected = splitArchiveThreat.copy(
    packageOrPath = info.packageName,
    displayName = label,
    packageName = info.packageName,
    scanSessionId = scanSessionId,
    apkSizeBytes = fileSize,
    sourceLocalPath = null,
    analysisStages = (completedStages + splitArchiveThreat.analysisStages + "SPLIT_ARCHIVE_INSPECTED" + "VERDICT").distinct()
   )
   audit(detected, start, scanSessionId, diagnostics)
   onStageChange("verdict")
   diagnostics?.stage(info.packageName, "verdict", "completed")
   return detected
  }
  val yaraXResult = apkAssessment.yaraResult
  if (yaraXResult.isComplete && yaraXResult.reason.isNullOrBlank()) {
   completedStages += if (appInfo.splitSourceDirs.isNullOrEmpty()) "YARA" else "YARA_SPLITS"
   diagnostics?.stage(info.packageName, "yara", "completed")
  } else {
   completedStages += "YARA_INCOMPLETE"
   diagnostics?.stage(info.packageName, "yara", "incomplete")
  }
  if (apkAssessment.splitIssues.isNotEmpty()) completedStages += "SPLIT_INCOMPLETE"
  val yaraThreat = yaraXResult.threatMatches.firstOrNull()
  if (yaraThreat != null) {
   val detected = evaluateWithEnsemble(
    yaraThreatResult(
     info.packageName, label, hashes.sha256, hashes.md5,
     yaraThreat, start, info.packageName, scanSessionId
    ),
    yaraXResult
   )
   audit(detected, start, scanSessionId, diagnostics)
   onStageChange("verdict")
   diagnostics?.stage(info.packageName, "verdict", "completed")
   return detected.copy(
    durationMs = elapsed(start), packageName = info.packageName, scanSessionId = scanSessionId,
    analysisStages = completedStages + "VERDICT"
   )
  }

  val embeddedArchive = scanArchiveContents(
   archive = apk,
   scanSessionId = scanSessionId,
   includeAllLeafEntries = false,
   ownerPackageName = info.packageName
  )
  embeddedArchive.finding?.takeIf { it.verdict == ScanVerdict.THREAT }?.let { archiveFinding ->
   val detected = archiveFinding.copy(
    packageOrPath = info.packageName,
    displayName = label,
    packageName = info.packageName,
    scanSessionId = scanSessionId,
    apkSizeBytes = fileSize,
    analysisStages = (
     completedStages + archiveFinding.analysisStages + "ARCHIVE_INSPECTED" +
      if (embeddedArchive.isPartial) listOf("ARCHIVE_INCOMPLETE") else emptyList()
    ).distinct()
   )
   audit(detected, start, scanSessionId, diagnostics)
   onStageChange("verdict")
   diagnostics?.stage(info.packageName, "verdict", "completed")
   return detected
  }

  onStageChange("ml")
  val mlProbability = if (isProtectedPlatformPackage(info.packageName, appInfo, diagnostics)) null else runMachineLearning(apk)
  completedStages += if (mlProbability != null) "ML" else "ML_UNAVAILABLE"
  diagnostics?.stage(info.packageName, "ml", if (mlProbability != null) "completed" else "unavailable")
  onStageChange("static_analysis")
  val baseDeepReport = deepStaticAnalyzer.analyze(info, apk, debugSigned)
  completedStages += "STATIC_ANALYSIS"
  val mergedDeepReport = mergeYaraXFindings(baseDeepReport, yaraXResult)
  val deepReport = mergedDeepReport.copy(mlProbability = mlProbability)
  val deepReasons = deepReport.findings.map { "[${it.ruleId}] ${it.evidence} (confidence ${it.confidence}%)" }
  reasons += deepReasons
  val combinedRiskScore = maxOf(adjustedRiskScore, deepReport.riskScore)
  val assessed = evaluateUnmatched(info.packageName, label, hashes.sha256, hashes.md5, reasons, combinedRiskScore, sha1 = hashes.sha1, report = deepReport)
   .copy(riskReport = deepReport, mlProbability = deepReport.mlProbability)
  val firstSuspiciousYara = yaraXResult.suspiciousMatches.firstOrNull()
  var output = assessed
  if (firstSuspiciousYara != null) {
   output = output.copy(
    malwareName = firstSuspiciousYara.malwareName ?: firstSuspiciousYara.ruleIdentifier
   )
  }
  output = evaluateWithEnsemble(
   output,
   yaraXResult,
   isSystemApp = isProtectedPlatformPackage(info.packageName, appInfo, diagnostics)
  )
  output = mergeArchiveSuspicion(output, embeddedArchive.finding)
  output = mergeArchiveSuspicion(output, apkAssessment.archiveFinding)
  onStageChange("verdict")
  output = ScanCoveragePolicy.applyYaraCoverage(output, yaraXResult.state, yaraXResult.reason)
  if (apkAssessment.splitIssues.isNotEmpty()) {
   output = ScanCoveragePolicy.applyPartialCoverage(
    output, "SPLIT_INCOMPLETE", apkAssessment.splitIssues.joinToString("; ")
   )
  }
  if (embeddedArchive.isPartial) {
   output = ScanCoveragePolicy.applyPartialCoverage(
    output, "ARCHIVE_INCOMPLETE",
    embeddedArchive.partialReason ?: "An embedded ZIP/JAR entry could not be completely inspected."
   )
  } else if (embeddedArchive.inspectedEntries > 0) {
   output = output.copy(analysisStages = (output.analysisStages + "ARCHIVE_INSPECTED").distinct())
  }
  if (apkAssessment.archiveIssues.isNotEmpty()) {
   output = ScanCoveragePolicy.applyPartialCoverage(
    output, "ARCHIVE_INCOMPLETE", apkAssessment.archiveIssues.joinToString("; ")
   )
  } else if (apkAssessment.archiveFinding != null) {
   output = output.copy(analysisStages = (output.analysisStages + "SPLIT_ARCHIVE_INSPECTED").distinct())
  }
  val finalStage = if (output.verdict == ScanVerdict.NOT_SCANNED) "VERDICT_PENDING" else "VERDICT"
  diagnostics?.stage(info.packageName, "verdict", if (finalStage == "VERDICT") "completed" else "pending_retry")
  audit(output, start, scanSessionId, diagnostics)
  return output.copy(
   durationMs = elapsed(start), packageName = info.packageName, scanSessionId = scanSessionId,
   analysisStages = (completedStages + output.analysisStages + finalStage).distinct()
  )
 }
 private suspend fun ensureCurrentAppScanCacheProfile(): Boolean =
  appScanCacheProfileMutex.withLock {
   if (appScanCacheProfileReady) return@withLock true
   try {
    val preferences = context.getSharedPreferences("safe_mobile_app_scan_cache", Context.MODE_PRIVATE)
    val currentProfile = preferences.getInt("profile_version", 0)
    if (currentProfile != APP_SCAN_CACHE_PROFILE_VERSION) {
     // Old cache rows predate split-APK and embedded-archive coverage. Never reuse them.
     dao.clearAppScanCache()
     if (!preferences.edit().putInt("profile_version", APP_SCAN_CACHE_PROFILE_VERSION).commit()) {
      Log.w("ScanDebug", "pkg_cache_bypass reason=cache_profile_version_not_persisted")
      return@withLock false
     }
    }
    appScanCacheProfileReady = true
    true
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    Log.w("ScanDebug", "pkg_cache_bypass reason=cache_profile_invalidation_failed", error)
    false
   }
  }

 private suspend fun scanPackageApks(
  baseApk: File,
  splitPaths: Array<String>?,
  packageName: String,
  displayName: String,
  scanSessionId: String,
  apkBytes: Long?,
  diagnostics: PackageScanDiagnostics?
 ): PackageApkAssessment {
  val results = mutableListOf<YaraXScanResult>()
  val splitIssues = mutableListOf<String>()
  val archiveIssues = mutableListOf<String>()
  var archiveFinding: ScanResult? = null
  val allSplits = splitPaths.orEmpty().distinct()
  if (allSplits.size > MAX_SPLIT_APK_COUNT) {
   splitIssues += "Split APK count limit exceeded; only the first $MAX_SPLIT_APK_COUNT splits were inspected."
  }
  results += withContext(Dispatchers.Default) { yaraXScanner.scanApk(baseApk, allowManifestOnly = true) }

  allSplits.take(MAX_SPLIT_APK_COUNT).forEach { path ->
   currentCoroutineContext().ensureActive()
   val split = File(path)
   if (!split.isFile || !split.canRead()) {
    splitIssues += "Split APK unavailable: ${split.name.take(120)}"
    return@forEach
   }
   try {
    val hashes = withContext(Dispatchers.Default) { calculator.calculate(split) }
    val threat = findExactHashThreat(
     "$packageName:${split.name}", displayName,
     hashes.sha256, hashes.md5, hashes.sha1, hashes.bytesRead
    )
    if (threat != null) {
     return PackageApkAssessment(
      yaraResult = ScanCoveragePolicy.combineYara(results, splitIssues),
      exactThreat = threat.copy(
       packageName = packageName,
       scanSessionId = scanSessionId,
       apkSizeBytes = apkBytes,
       reasons = threat.reasons + "Exact hash match in split APK ${split.name.take(120)}.",
       analysisStages = listOf("SPLIT_HASH", "VERDICT")
      ),
      splitIssues = splitIssues
     )
    }
    results += withContext(Dispatchers.Default) {
     yaraXScanner.scanApk(split, allowManifestOnly = true)
    }
    val splitArchive = scanArchiveContents(
     archive = split,
     scanSessionId = scanSessionId,
     includeAllLeafEntries = false,
     ownerPackageName = packageName
    )
    val splitFinding = splitArchive.finding
    if (splitFinding != null && (
      splitFinding.verdict == ScanVerdict.THREAT ||
       (splitFinding.verdict == ScanVerdict.SUSPICIOUS && archiveFinding?.verdict != ScanVerdict.THREAT)
     )
    ) {
     archiveFinding = splitFinding
    }
    if (splitArchive.isPartial) {
     archiveIssues += splitArchive.partialReason
      ?: "Embedded ZIP/JAR inspection was incomplete in split APK ${split.name.take(120)}."
    }
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    val userId = diagnostics?.userId ?: (android.os.Process.myUid() / 100000)
    diagnostics?.fail(packageName, "split_scan", error)
    Log.w("ScanDebug", "pkg_split_incomplete pkg=$packageName split=${split.name} userId=$userId", error)
    splitIssues += "Split APK scan incomplete: ${split.name.take(120)} (${error.javaClass.simpleName})."
   }
  }
  return PackageApkAssessment(
   yaraResult = ScanCoveragePolicy.combineYara(results, splitIssues),
   splitIssues = splitIssues,
   archiveFinding = archiveFinding,
   archiveIssues = archiveIssues
  )
 }

 private suspend fun scanArchiveContents(
  archive: File,
  scanSessionId: String,
  includeAllLeafEntries: Boolean,
  ownerPackageName: String? = null
 ): ArchiveAssessment {
  var finding: ScanResult? = null
  var yaraIncompleteReason: String? = null
  val inspected = BoundedZipArchiveInspector.inspect(
   archive = archive,
   includeAllLeafEntries = includeAllLeafEntries,
   maxDepth = 3
  ) { entry ->
   val leafName = entry.entryName.substringAfterLast('/').take(160)
   if (leafName.endsWith(".apk", ignoreCase = true)) {
    val staged = File.createTempFile("archive-apk-", ".apk", context.cacheDir)
    try {
     staged.outputStream().use { it.write(entry.bytes) }
     val nested = scanFile(
      staged,
      persistAllAudit = false,
      inspectEmbeddedArchives = false
     )
     if (nested.verdict == ScanVerdict.NOT_SCANNED || ScanCoveragePolicy.isPartial(nested)) {
      yaraIncompleteReason = yaraIncompleteReason ?: nested.reasons.lastOrNull()
       ?: "An embedded APK could not be fully inspected."
     }
     val candidate = nested.copy(
      packageOrPath = entry.entryName,
      displayName = entry.entryName.take(240),
      packageName = ownerPackageName,
      scanSessionId = scanSessionId,
      sourceLocalPath = null,
      reasons = (nested.reasons + "Embedded APK entry: ${entry.entryName.take(240)}").distinct()
     )
     if (candidate.verdict == ScanVerdict.THREAT ||
      (candidate.verdict == ScanVerdict.SUSPICIOUS && finding?.verdict != ScanVerdict.THREAT)
     ) finding = candidate
    } finally {
     staged.delete()
    }
   } else {
    val hashes = withContext(Dispatchers.Default) {
     calculator.calculate(ByteArrayInputStream(entry.bytes))
    }
    val exact = findExactHashThreat(
     entry.entryName, entry.entryName, hashes.sha256, hashes.md5,
     hashes.sha1, hashes.bytesRead
    )
    if (exact != null) {
     val candidate = exact.copy(
      packageName = ownerPackageName,
      scanSessionId = scanSessionId,
      reasons = exact.reasons + "Exact hash match in archive entry: ${entry.entryName.take(240)}."
     )
     if (candidate.verdict == ScanVerdict.THREAT) finding = candidate
    } else if (entry.bytes.isNotEmpty()) {
     val yara = withContext(Dispatchers.Default) {
      yaraXScanner.scanComponent(entry.entryName, entry.bytes)
     }
     if (yara.state == YaraXScanState.DISABLED || yara.state == YaraXScanState.NOT_SCANNED) {
      yaraIncompleteReason = yaraIncompleteReason ?: yara.reason
       ?: "YARA-X did not complete for archive entry ${entry.entryName.take(160)}."
     }
     val threatMatch = yara.threatMatches.firstOrNull()
     val suspiciousMatch = yara.suspiciousMatches.firstOrNull()
     val candidate = when {
      threatMatch != null -> yaraThreatResult(
       entry.entryName, entry.entryName, hashes.sha256, hashes.md5,
       threatMatch, System.nanoTime(), ownerPackageName, scanSessionId
      )
      suspiciousMatch != null -> ScanResult(
       entry.entryName, entry.entryName, hashes.sha256, hashes.md5,
       ScanVerdict.SUSPICIOUS,
       listOf("YARA-X ${suspiciousMatch.ruleIdentifier}: ${suspiciousMatch.description}"),
       0L
      ).copy(
       packageName = ownerPackageName,
       scanSessionId = scanSessionId,
       detectionSource = DetectionSource.YARA,
       malwareName = suspiciousMatch.malwareName ?: suspiciousMatch.ruleIdentifier,
       riskScore = 0.55f
      )
      else -> null
     }
     if (candidate != null) {
      val decorated = candidate.copy(
       reasons = candidate.reasons + "Archive entry: ${entry.entryName.take(240)}."
      )
      if (decorated.verdict == ScanVerdict.THREAT ||
       (decorated.verdict == ScanVerdict.SUSPICIOUS && finding?.verdict != ScanVerdict.THREAT)
      ) finding = decorated
     }
    }
   }
  }
  val reasons = listOfNotNull(
   inspected.reason,
   yaraIncompleteReason?.takeIf { it.isNotBlank() }
  ).distinct()
  return ArchiveAssessment(
   finding = finding,
   inspectedEntries = inspected.inspectedEntries,
   partialReason = reasons.joinToString(" ").take(500).takeIf { it.isNotBlank() }
  )
 }

 private fun mergeArchiveSuspicion(
  result: ScanResult,
  archiveFinding: ScanResult?
 ): ScanResult {
  if (archiveFinding?.verdict != ScanVerdict.SUSPICIOUS) return result
  val cleanPrimary = result.verdict == ScanVerdict.NO_MATCH
  return result.copy(
   verdict = if (cleanPrimary) ScanVerdict.SUSPICIOUS else result.verdict,
   reasons = (result.reasons + archiveFinding.reasons).distinct(),
   riskScore = maxOf(result.riskScore, archiveFinding.riskScore),
   detectionSource = if (cleanPrimary) archiveFinding.detectionSource else result.detectionSource,
   malwareName = result.malwareName ?: archiveFinding.malwareName,
   confidence = maxOf(result.confidence, archiveFinding.confidence)
  )
 }

 private fun hasZipSignature(file: File): Boolean = try {
  file.inputStream().use { input ->
   val signature = ByteArray(4)
   input.read(signature) == signature.size &&
    signature[0] == 0x50.toByte() &&
    signature[1] == 0x4b.toByte() &&
    signature[2] in setOf(0x03.toByte(), 0x05.toByte(), 0x07.toByte()) &&
    signature[3] in setOf(0x04.toByte(), 0x06.toByte(), 0x08.toByte())
  }
 } catch (_: Exception) {
  false
 }

 private fun readBoundedPrefix(input: InputStream): ByteArray {
  val buffer = ByteArray(eicarProbeBytes)
  var total = 0
  while (total < buffer.size) {
   val count = input.read(buffer, total, buffer.size - total)
   if (count <= 0) break
   total += count
  }
  return if (total == buffer.size) buffer else buffer.copyOf(total)
 }

 private fun trustedResult(name: String, session: String, start: Long) =
  result(name, name, null, null, ScanVerdict.NO_MATCH,
   listOf(context.getString(R.string.trusted_app_explanation)), start).copy(
    packageName = name, scanSessionId = session, trustedByUser = true,
    scanSource = ScanSource.USER_TRUSTED, analysisStages = listOf("USER_TRUSTED", "VERDICT"))
 private suspend fun findExactHashThreat(
  key: String, label: String, sha: String, md5: String, sha1: String?, fileSize: Long?
 ): ScanResult? {
  // The fixed EICAR digest is a local fallback and is checked before optional
  // signed-database, local Room, or threat-feed lookups.
  if (sha.equals(HashMatcher.EICAR_SHA256, ignoreCase = true)) {
   return ScanResult(
    key, label, sha, md5, ScanVerdict.THREAT,
    listOf(HashMatcher.EICAR_MALWARE_NAME), 0
   ).copy(
    threatEventId = UUID.randomUUID().toString(),
    riskScore = 1f,
    sha1 = sha1,
    detectionSource = DetectionSource.HASH,
    malwareName = HashMatcher.EICAR_MALWARE_NAME
   )
  }

  val encrypted = hashStore.protectHash(sha)
  val signedHashMatch = hashDatabaseManager?.lookup(sha, md5, sha1, fileSize)
  if (signedHashMatch != null) {
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT,
    listOf(context.getString(R.string.hashdb_match, signedHashMatch.algorithm.token.uppercase(), signedHashMatch.threatName)), 0)
    .copy(threatEventId = UUID.randomUUID().toString(), riskScore = 1f, sha1 = sha1, reasonTexts = listOf(UiText(R.string.hashdb_match, listOf(signedHashMatch.algorithm.token.uppercase(), signedHashMatch.threatName))), detectionSource = DetectionSource.SIGNED_DATABASE, malwareName = signedHashMatch.threatName)
  }
  val threat = dao.findThreatByEncryptedHash(encrypted)
  if (threat != null) {
   val family = revealMetadataOrPlaintext(threat.malwareFamily, "family")
   val level = revealMetadataOrPlaintext(threat.threatLevel, "level")
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT, listOf(context.getString(R.string.hash_match, family, level)), 0).copy(threatEventId = UUID.randomUUID().toString(), riskScore = 1f, sha1 = sha1, reasonTexts = listOf(UiText(R.string.hash_match, listOf(family, UiText(SecurityText.severity(level))))), detectionSource = DetectionSource.HASH, malwareName = family)
  }
  val feedThreat = threatIntelligenceRepository?.lookupHash(sha, md5, sha1, fileSize)
  if (feedThreat != null) {
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT,
    listOf(context.getString(R.string.threat_feed_hash_match, feedThreat.threatName, feedThreat.source)), 0)
    .copy(
     threatEventId = UUID.randomUUID().toString(),
     riskScore = 1f,
     sha1 = sha1,
     reasonTexts = listOf(UiText(R.string.threat_feed_hash_match, listOf(feedThreat.threatName, feedThreat.source))),
     detectionSource = DetectionSource.THREAT_INTELLIGENCE_FEED,
     malwareName = feedThreat.threatName
    )
  }

  // Bundled signatures are a final local exact-match layer. Existing signed
  // DB, encrypted Room allow/trust state, and opted-in feed checks retain their
  // established precedence; every Bloom-filter candidate is exact-verified.
  val bundled = loadBundledHashSnapshot()
  val bundledMatch = hashMatcher.matchDigests(md5, sha, bundled.hashes, bundled.bloomFilter)
  if (!bundledMatch.isThreat) return null
  val name = bundledMatch.malwareName ?: "Known hash signature"
  return ScanResult(key, label, sha, md5, ScanVerdict.THREAT, listOf(name), 0).copy(
   threatEventId = UUID.randomUUID().toString(),
   riskScore = 1f,
   sha1 = sha1,
   detectionSource = DetectionSource.HASH,
   malwareName = name
  )
 }
 // Invoked only after all exact-hash engines return no match.
 private suspend fun evaluateUnmatched(
  key: String, label: String, sha: String, md5: String, heuristic: List<String>,
  score: Int, sha1: String? = null, report: RiskReport? = null
 ): ScanResult {
  val encrypted = hashStore.protectHash(sha)
  // An allow/dismiss choice can suppress heuristics, never an exact known-malware match.
  if (dao.isHashWhitelisted(encrypted)) return ScanResult(key, label, sha, md5, ScanVerdict.NO_MATCH, listOf(context.getString(R.string.hash_allowlisted)), 0).copy(sha1 = sha1, reasonTexts = listOf(UiText(R.string.hash_allowlisted)))
  val verdict = if (score >= 45) ScanVerdict.SUSPICIOUS else ScanVerdict.NO_MATCH
  val notes = if (heuristic.isEmpty()) listOf(context.getString(R.string.no_match_detail)) else heuristic + context.getString(R.string.risk_review)
  return ScanResult(key, label, sha, md5, verdict, notes, 0).copy(
   riskScore = score.coerceIn(0, 100) / 100f,
   sha1 = sha1,
   reasonTexts = SecurityText.reasons(context, notes, report),
   detectionSource = if (verdict == ScanVerdict.SUSPICIOUS) DetectionSource.HEURISTIC else DetectionSource.NONE
  )
 }
 // Stream-only scans still check exact hashes before allowing heuristic verdicts.
 private suspend fun evaluate(
  key: String, label: String, sha: String, md5: String, heuristic: List<String>,
  score: Int, sha1: String? = null, fileSize: Long? = null, report: RiskReport? = null
 ): ScanResult = evaluateWithEnsemble(
  findExactHashThreat(key, label, sha, md5, sha1, fileSize)
   ?: evaluateUnmatched(key, label, sha, md5, heuristic, score, sha1, report)
 )
 private fun installedApkBytes(appInfo: ApplicationInfo?): Long? {
  appInfo ?: return null
  val paths = (listOfNotNull(appInfo.sourceDir) + appInfo.splitSourceDirs.orEmpty()).distinct()
  var bytes = 0L
  var readable = false
  paths.forEach { path ->
   try {
    val file = File(path)
    if (file.isFile && file.canRead()) {
     val size = file.length().coerceAtLeast(0L)
     bytes = if (Long.MAX_VALUE - bytes < size) Long.MAX_VALUE else bytes + size
     readable = true
    }
   } catch (_: Exception) { }
  }
  return if (readable) bytes else null
 }

 private fun logPackageMetadata(info: PackageInfo, diagnostics: PackageScanDiagnostics) {
  val app = info.applicationInfo
  val flags = app?.flags ?: 0
  // getInstalledPackages(0) does not request MATCH_ARCHIVED_PACKAGES.
  val archivedQuery = "not_requested"
  val splitCount = try {
   app?.splitSourceDirs?.size ?: 0
  } catch (error: Exception) {
   Log.w("ScanDebug", "pkg_meta_read_failed pkg=${info.packageName} field=splitCount userId=${diagnostics.userId}", error)
   -1
  }
  val apkBytes = try {
   installedApkBytes(app) ?: -1L
  } catch (error: Exception) {
   Log.w("ScanDebug", "pkg_meta_read_failed pkg=${info.packageName} field=apkBytes userId=${diagnostics.userId}", error)
   -1L
  }
  Log.i(
   "ScanDebug",
   "pkg_meta pkg=${info.packageName} userId=${diagnostics.userId}" +
    " system=${flags and ApplicationInfo.FLAG_SYSTEM != 0}" +
    " updatedSystem=${flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0}" +
    " external=${flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE != 0}" +
    " archivedQuery=$archivedQuery" +
    " splitCount=$splitCount" +
    " apkBytesIncludingSplits=$apkBytes"
  )
 }

 private fun loadPackageLabelOrFallback(
  info: PackageInfo,
  diagnostics: PackageScanDiagnostics?,
  onStageChange: (String) -> Unit
 ): String {
  onStageChange("label")
  return try {
   info.applicationInfo?.loadLabel(pm)?.toString().orEmpty().ifBlank { info.packageName }
  } catch (error: Exception) {
   diagnostics?.fail(info.packageName, "label", error)
   info.packageName
  }
 }

 private suspend fun auditSafely(
  result: ScanResult,
  start: Long,
  scanSessionId: String,
  diagnostics: PackageScanDiagnostics? = null
 ) {
  try {
   audit(result, start, scanSessionId, diagnostics)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   val stage = (error as? ScanPublishStageException)?.stage ?: "room_insert"
   val packageName = result.packageName ?: result.packageOrPath
   if (diagnostics != null) {
    diagnostics.fail(packageName, stage, error.cause ?: error)
   } else {
    val userId = android.os.Process.myUid() / 100000
    Log.e("ScanDebug", "pkg_fail pkg=$packageName stage=$stage userId=$userId", error)
   }
  }
 }

 private suspend fun audit(
  result: ScanResult,
  start: Long,
  scanSessionId: String,
  diagnostics: PackageScanDiagnostics? = null
 ) {
  var stage = "encrypt"
  try {
   val encryptedLabel = hashStore.protectPrivateText(result.packageOrPath.take(250), "scan-label")
   val encryptedHash = result.sha256?.let(hashStore::protectHash).orEmpty()
   stage = "room_insert"
   dao.insertAudit(ScanAudit(
    packageOrPath = encryptedLabel,
    hash = encryptedHash,
    scanTimestamp = System.currentTimeMillis(),
    verdict = result.verdict.name,
    scanDuration = elapsed(start),
    scanSessionId = scanSessionId,
    threatEventId = result.threatEventId.orEmpty()
   ))
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   throw ScanPublishStageException(stage, error)
  }
 }

 private fun revealMetadataOrPlaintext(value: String, purpose: String): String =
  try {
   hashStore.revealMetadata(value, purpose)
  } catch (error: Exception) {
   val userId = android.os.Process.myUid() / 100000
   Log.e("ScanDebug", "metadata_decode_failed purpose=$purpose userId=$userId", error)
   value
  }

 private val trustedSignerDigests: Set<String> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
  loadTrustedSignerDigests()
 }

 /**
  * Fetches only the package fields consumed by risk analysis. Signing data is
  * intentionally requested in a separate guarded PackageManager call because
  * some OEM package providers fail when signing and component metadata are
  * requested together.
  */
 private fun loadPackageInfoForScan(
  packageName: String,
  diagnostics: PackageScanDiagnostics? = null
 ): PackageInfo {
  val scanFlags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
   PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
  val info = getPackageInfoCompat(packageName, scanFlags)
  val signerInfo = loadPackageSigningInfo(packageName, diagnostics)
  if (signerInfo != null) {
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
    info.signingInfo = signerInfo.signingInfo
   } else {
    @Suppress("DEPRECATION")
    run { info.signatures = signerInfo.signatures }
   }
  }
  return info
 }

 private fun getPackageInfoCompat(packageName: String, flags: Int): PackageInfo =
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
   pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
  } else {
   @Suppress("DEPRECATION")
   pm.getPackageInfo(packageName, flags)
  }

 /** Signing metadata is optional for the scan; unreadable signers never abort package enumeration. */
 private fun loadPackageSigningInfo(
  packageName: String,
  diagnostics: PackageScanDiagnostics? = null
 ): PackageInfo? = try {
  getPackageInfoCompat(packageName, signingFlags())
 } catch (error: Exception) {
  if (diagnostics != null) diagnostics.fail(packageName, "resolve", error)
  else {
   val userId = android.os.Process.myUid() / 100000
   Log.e("ScanDebug", "pkg_fail pkg=$packageName stage=resolve userId=$userId", error)
  }
  Log.w(TAG, "Package signing metadata unavailable for " + packageName + "; scanning without signer trust.", error)
  null
 }

 /** Trust is based on certificate equality with the installed Play Services/Play Store signers. */
 private fun isSignedByKnownTrustedCertificate(
  packageName: String,
  diagnostics: PackageScanDiagnostics? = null
 ): Boolean {
  val trusted = trustedSignerDigests
  if (trusted.isEmpty()) return false
  val signerInfo = loadPackageSigningInfo(packageName, diagnostics) ?: return false
  return signingCertificateDigests(signerInfo, diagnostics).any { it in trusted }
 }

 private fun isSignedByKnownTrustedCertificate(
  info: PackageInfo,
  diagnostics: PackageScanDiagnostics? = null
 ): Boolean {
  val trusted = trustedSignerDigests
  if (trusted.isEmpty()) return false
  return signingCertificateDigests(info, diagnostics).any { it in trusted }
 }

 private fun loadTrustedSignerDigests(): Set<String> =
  TRUSTED_CERTIFICATE_ANCHOR_PACKAGES.flatMap { packageName ->
   val anchor = loadPackageSigningInfo(packageName)
   anchor?.let { signingCertificateDigests(it) }.orEmpty()
  }.toSet()

 private fun signingCertificateDigests(
  info: PackageInfo,
  diagnostics: PackageScanDiagnostics? = null
 ): Set<String> {
  val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
   val signingInfo = info.signingInfo
   if (signingInfo == null) emptyList()
   else (
    signingInfo.apkContentsSigners?.toList().orEmpty() +
     signingInfo.signingCertificateHistory?.toList().orEmpty()
    ).distinct()
  } else {
   @Suppress("DEPRECATION")
   info.signatures?.toList().orEmpty()
  }
  return signatures.mapNotNull { signature ->
   try {
    MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
     .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
   } catch (error: Exception) {
    if (diagnostics != null) diagnostics.fail(info.packageName, "resolve", error)
    else {
     val userId = android.os.Process.myUid() / 100000
     Log.e("ScanDebug", "pkg_fail pkg=${info.packageName} stage=resolve userId=$userId", error)
    }
    null
   }
  }.toSet()
 }

 private fun isDebugSigned(
  info: PackageInfo,
  diagnostics: PackageScanDiagnostics? = null
 ): Boolean = try {
  val signatureBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
   info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
  } else {
   @Suppress("DEPRECATION")
   info.signatures?.firstOrNull()?.toByteArray()
  } ?: return false
  val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(signatureBytes)) as X509Certificate
  val subject = cert.subjectX500Principal.name
  subject.contains("CN=Android Debug", true) || subject.contains("CN=AndroidDebug", true)
 } catch (error: Exception) {
  if (diagnostics != null) diagnostics.fail(info.packageName, "resolve", error)
  else {
   val userId = android.os.Process.myUid() / 100000
   Log.e("ScanDebug", "pkg_fail pkg=${info.packageName} stage=resolve userId=$userId", error)
  }
  false
 }

 private fun signingFlags(): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else {
  @Suppress("DEPRECATION")
  PackageManager.GET_SIGNATURES
 }
 private fun result(key: String, label: String, sha: String?, md5: String?, verdict: ScanVerdict, reasons: List<String>, start: Long) =
  ScanResult(key, label, sha, md5, verdict, reasons, elapsed(start), reasonTexts = SecurityText.reasons(context, reasons))
 private fun elapsed(start: Long) = ((System.nanoTime() - start) / 1_000_000L).coerceAtLeast(0)
}

