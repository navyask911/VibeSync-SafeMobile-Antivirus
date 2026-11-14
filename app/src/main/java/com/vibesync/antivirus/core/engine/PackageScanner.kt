package com.vibesync.antivirus.core.engine
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
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

private const val SAFE_SYSTEM_PACKAGE_LABEL = "Safe (System App)"
private const val SAFE_TRUSTED_CERTIFICATE_LABEL = "Safe (Trusted Certificate)"
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

 private data class BundledHashSnapshot(
  val hashes: Set<String>,
  val bloomFilter: BloomFilter<String>
 )

 private val signatureDatabaseParser = SignatureDatabaseParser()
 private val bloomFilterBuilder = BloomFilterBuilder()
 private val hashMatcher = HashMatcher()
 private val signatureDatabaseMutex = Mutex()

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
  val addedScore = when {
   scan.suspiciousMatches.any { it.severity == "critical" || it.severity == "high" } -> 65
   scan.suspiciousMatches.isNotEmpty() -> 45
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

 private fun markIncompleteYaraIfOtherwiseClean(
  result: ScanResult,
  yaraResult: YaraXScanResult?
 ): ScanResult {
  if (result.verdict != ScanVerdict.NO_MATCH) return result
  if (yaraResult?.state != YaraXScanState.DISABLED &&
   yaraResult?.state != YaraXScanState.NOT_SCANNED
  ) return result
  return result.copy(
   verdict = ScanVerdict.NOT_SCANNED,
   reasons = result.reasons + context.getString(R.string.file_could_not_read)
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
  yaraResult: YaraXScanResult? = null
 ): ScanResult = ThreatEnsembleEvaluator.evaluate(
  result.copy(yaraVerdict = rawYaraVerdict(yaraResult))
 )

 private suspend fun runMachineLearning(apk: File): Float? {
  val features = drebinFeatureExtractor.extractFeaturesAsync(apk)
  // Phase 3 records the research probability only. Phase 4 owns any verdict fusion.
  return tfliteInferenceEngine.runInference(features)
 }

 fun installedAppInventory(): List<InstalledAppItem> {
  @Suppress("DEPRECATION")
  val packages = pm.getInstalledPackages(0)
  return packages.asSequence().filter { info ->
   val flags = info.applicationInfo?.flags ?: return@filter false
   ProtectedPackagePolicy.isUserInstalled(flags, info.packageName, context.packageName)
  }.map { info ->
   val label = runCatching { info.applicationInfo?.loadLabel(pm)?.toString() }
    .getOrNull().orEmpty().ifBlank { info.packageName }
   InstalledAppItem(info.packageName, label)
  }.distinctBy { it.packageName }.sortedBy { it.displayName.lowercase(java.util.Locale.getDefault()) }.toList()
 }
 suspend fun scanInstalledApps(progress: suspend (processed: Int, total: Int) -> Unit = { _, _ -> }): List<ScanResult> =
   scanInstalledAppsForSession(UUID.randomUUID().toString(), progress)

 suspend fun scanInstalledAppsForSession(
  scanSessionId: String,
  progress: suspend (processed: Int, total: Int) -> Unit = { _, _ -> }
 ): List<ScanResult> = coroutineScope {
  val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or
   PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or
   PackageManager.GET_PROVIDERS or signingFlags()
  val packages = pm.getInstalledPackages(flags).filter { info ->
   val appInfo = info.applicationInfo
   val isSystemApp = appInfo != null &&
    (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
   val isUpdatedSystemApp = appInfo != null &&
    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
   appInfo != null && info.packageName != context.packageName &&
    (isSystemApp || isUpdatedSystemApp ||
     ProtectedPackagePolicy.isUserInstalled(appInfo.flags, info.packageName, context.packageName) ||
     isSignedByKnownTrustedCertificate(info))
  }

  // Keep CPU-heavy work bounded on older devices to avoid parallel APK/DEX memory spikes.
  val semaphore = Semaphore(Runtime.getRuntime().availableProcessors().coerceAtMost(4))
  val processedCount = AtomicInteger(0)
  val progressMutex = Mutex()
  progress(0, packages.size)

  val results = packages.map { info ->
   async(Dispatchers.Default) {
    val scanned = semaphore.withPermit {
     currentCoroutineContext().ensureActive()
     val packageStart = System.nanoTime()
     try {
      scanPackage(info, scanSessionId)
     } catch (cancelled: CancellationException) {
      throw cancelled
     } catch (_: Exception) {
      val failed = result(
       info.packageName,
       info.packageName,
       null,
       null,
       ScanVerdict.NOT_SCANNED,
       listOf(context.getString(R.string.file_could_not_read)),
       packageStart
      ).copy(packageName = info.packageName, scanSessionId = scanSessionId)
      auditSafely(failed, packageStart, scanSessionId)
      failed
     }
    }
    progressMutex.withLock {
     progress(processedCount.incrementAndGet(), packages.size)
    }
    scanned
   }
  }.awaitAll()

  results.sortedBy { when (it.verdict) {
   ScanVerdict.THREAT -> 0
   ScanVerdict.SUSPICIOUS -> 1
   ScanVerdict.NOT_SCANNED -> 2
   ScanVerdict.NO_MATCH -> 3
  } }
 }
 suspend fun scanInstalledPackage(name: String, scanSessionId: String = UUID.randomUUID().toString()): ScanResult? {
  if (trustedAppStore.isTrusted(name)) return trustedResult(name, scanSessionId, System.nanoTime())
  if (name == context.packageName) return null
  val info = try {
   pm.getPackageInfo(name, PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingFlags())
  } catch (_: PackageManager.NameNotFoundException) {
   return null
  } catch (_: SecurityException) {
   return result(name, name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.package_metadata_missing)), System.nanoTime()).copy(packageName = name, scanSessionId = scanSessionId)
  }
  val appInfo = info.applicationInfo ?: return null
  val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
  val isUpdatedSystemApp = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
  val isTrustedCertificate = isSignedByKnownTrustedCertificate(info)
  if (!ProtectedPackagePolicy.isUserInstalled(appInfo.flags, info.packageName, context.packageName) &&
   !isSystemApp && !isUpdatedSystemApp && !isTrustedCertificate
  ) return null
  return scanPackage(info, scanSessionId)
 }
 suspend fun scanFile(file: File, persistAllAudit: Boolean = true): ScanResult {
  val start = System.nanoTime()
  val scanSessionId = UUID.randomUUID().toString()
  if (!file.isFile || !file.canRead()) {
   val failed = result(file.name, file.name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_not_readable)), start)
   auditSafely(failed, start, scanSessionId)
   return failed.copy(sourceLocalPath = file.absolutePath, scanSessionId = scanSessionId)
  }
  return try {
   // Read only package identity before any hash, DEX, model or heuristic work.
   val identity = pm.getPackageArchiveInfo(file.absolutePath, 0)?.packageName
   if (identity != null && trustedAppStore.isTrusted(identity)) {
    return trustedResult(identity, scanSessionId, start).copy(sourceLocalPath = file.absolutePath)
   }
   val hash = calculator.calculate(file)
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

  val yaraXResult = if (file.extension.equals("apk", ignoreCase = true)) {
   yaraXScanner.scanApk(file)
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

  val mlProbability = if (file.extension.equals("apk", ignoreCase = true)) {
   runMachineLearning(file)
  } else null
  val staticReport = if (file.extension.equals("apk", ignoreCase = true)) {
    val archiveInfo = try {
     val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or signingFlags()
     if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      pm.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
     } else {
      @Suppress("DEPRECATION")
      pm.getPackageArchiveInfo(file.absolutePath, flags)
     }
    } catch (_: Exception) { null }
    archiveInfo?.applicationInfo?.apply { sourceDir = file.absolutePath; publicSourceDir = file.absolutePath }
    val baseReport = deepStaticAnalyzer.analyze(archiveInfo, file, archiveInfo?.let(::isDebugSigned) == true)
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
   output = evaluateWithEnsemble(output, yaraXResult)
   output = markIncompleteYaraIfOtherwiseClean(output, yaraXResult)
   if (!file.extension.equals("apk", ignoreCase = true)) {
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
   if (zipHeader || label.substringBefore('?').endsWith(".apk", ignoreCase = true)) {
    // A content URI does not expose package identity. Stage APK bytes in app-private
    // cache so PackageManager can read the manifest before any detection engine.
    val staged = File.createTempFile("trust-identity-", ".apk", context.cacheDir)
    try {
     inputStream.use { input -> staged.outputStream().use { output ->
      val buffer = ByteArray(64 * 1024)
      var total = 0L
      while (true) {
       currentCoroutineContext().ensureActive()
       val read = input.read(buffer)
       if (read < 0) break
       total += read
       require(total <= 512L * 1024 * 1024) { "APK staging limit exceeded" }
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
   val hash = inputStream.use { calculator.calculate(it) }
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
 private suspend fun scanPackage(info: PackageInfo, scanSessionId: String): ScanResult {
  val start = System.nanoTime()
  if (trustedAppStore.isTrusted(info.packageName)) {
   return trustedResult(info.packageName, scanSessionId, start)
  }

  // System and known platform-signed apps are safe-listed before any file hashing or deep analysis.
  val appInfo = info.applicationInfo
  val isSystemApp = appInfo != null &&
   (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
  val isUpdatedSystemApp = appInfo != null &&
   (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
  val isTrustedCertificate = appInfo != null && !isSystemApp && !isUpdatedSystemApp &&
   isSignedByKnownTrustedCertificate(info)

  // PackageInfo and sourceDir metadata are read before any hash, DEX, YARA or ML work.
  val apk = appInfo?.sourceDir?.let(::File)
  val fileSize = apk?.let { source -> runCatching { source.length() }.getOrNull() }
  val cached = try {
   dao.findAppScanCache(info.packageName)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   Log.w(TAG, "Could not read the installed-app scan cache.", error)
   null
  }

  if (isSystemApp || isUpdatedSystemApp || isTrustedCertificate) {
   val safeLabel = if (isSystemApp || isUpdatedSystemApp) {
    SAFE_SYSTEM_PACKAGE_LABEL
   } else {
    SAFE_TRUSTED_CERTIFICATE_LABEL
   }
   if (fileSize != null && cached != null &&
    cached.lastUpdateTime == info.lastUpdateTime && cached.fileSize == fileSize &&
    cached.verdict == ScanVerdict.NO_MATCH.name && cached.threatName == safeLabel
   ) {
    val label = runCatching { appInfo?.loadLabel(pm)?.toString() }
     .getOrNull().orEmpty().ifBlank { info.packageName }
    val cachedResult = ScanResult(
     packageOrPath = info.packageName,
     displayName = label,
     sha256 = cached.sha256.takeIf { it.isNotBlank() },
     md5 = null,
     verdict = ScanVerdict.NO_MATCH,
     reasons = listOf(safeLabel),
     durationMs = elapsed(start)
    ).copy(packageName = info.packageName, scanSessionId = scanSessionId)
    auditSafely(cachedResult, start, scanSessionId)
    return cachedResult
   }
   return safePlatformPackageResult(info, scanSessionId, start, fileSize, safeLabel)
  }

  if (fileSize != null && cached != null &&
   cached.lastUpdateTime == info.lastUpdateTime && cached.fileSize == fileSize
  ) {
   val cachedVerdict = runCatching { ScanVerdict.valueOf(cached.verdict) }.getOrNull()
   if (cachedVerdict != null) {
    val label = runCatching { appInfo?.loadLabel(pm)?.toString() }
     .getOrNull().orEmpty().ifBlank { info.packageName }
    val cachedResult = ScanResult(
     packageOrPath = info.packageName,
     displayName = label,
     sha256 = cached.sha256.takeIf { it.isNotBlank() },
     md5 = null,
     verdict = cachedVerdict,
     reasons = cached.threatName?.let(::listOf).orEmpty(),
     durationMs = elapsed(start)
    ).copy(
     packageName = info.packageName,
     scanSessionId = scanSessionId,
     malwareName = cached.threatName
    )
    // Keep scan history complete even though expensive file engines were bypassed.
    auditSafely(cachedResult, start, scanSessionId)
    return cachedResult
   }
  }

  val scanned = try {
   scanPackageUncached(info, scanSessionId)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   Log.w(TAG, "Installed-app scan failed; caching a not-scanned result.", error)
   val label = runCatching { appInfo?.loadLabel(pm)?.toString() }
    .getOrNull().orEmpty().ifBlank { info.packageName }
   result(
    info.packageName,
    label,
    null,
    null,
    ScanVerdict.NOT_SCANNED,
    listOf(context.getString(R.string.file_could_not_read)),
    start
   ).copy(packageName = info.packageName, scanSessionId = scanSessionId).also {
    auditSafely(it, start, scanSessionId)
   }
  }
  if (fileSize != null) {
   try {
    dao.upsertAppScanCache(
     AppScanCache(
      packageName = info.packageName,
      lastUpdateTime = info.lastUpdateTime,
      fileSize = fileSize,
      sha256 = scanned.sha256.orEmpty(),
      verdict = scanned.verdict.name,
      threatName = scanned.malwareName
     )
    )
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    Log.w(TAG, "Could not update the installed-app scan cache; scan result is still valid.", error)
   }
  }
  return scanned
 }

 private suspend fun safePlatformPackageResult(
  info: PackageInfo,
  scanSessionId: String,
  start: Long,
  fileSize: Long?,
  safeLabel: String
 ): ScanResult {
  val displayName = runCatching { info.applicationInfo?.loadLabel(pm)?.toString() }
   .getOrNull().orEmpty().ifBlank { info.packageName }
  val safeResult = ScanResult(
   packageOrPath = info.packageName,
   displayName = displayName,
   sha256 = null,
   md5 = null,
   verdict = ScanVerdict.NO_MATCH,
   reasons = listOf(safeLabel),
   durationMs = elapsed(start)
  ).copy(packageName = info.packageName, scanSessionId = scanSessionId)

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
    Log.w(TAG, "Could not cache the safe platform package result.", error)
   }
  }
  auditSafely(safeResult, start, scanSessionId)
  return safeResult
 }

 private suspend fun scanPackageUncached(info: PackageInfo, scanSessionId: String): ScanResult {
  val start = System.nanoTime()
  val appInfo = info.applicationInfo ?: run {
   val failed = result(info.packageName, info.packageName, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.package_metadata_missing)), start).copy(packageName = info.packageName, scanSessionId = scanSessionId)
   auditSafely(failed, start, scanSessionId)
   return failed
  }
  val label = appInfo.loadLabel(pm).toString()
  val permissions = info.requestedPermissions?.toSet().orEmpty()
  val accessibility = info.services.orEmpty().any { it.permission == PermissionRiskAnalyzer.BIND_ACCESSIBILITY }
  val risk = riskAnalyzer.assess(permissions, accessibility)
  val deviceIntegrity = integrityChecker.check()
  val adjustedRiskScore = (risk.score * deviceIntegrity.riskMultiplier).roundToInt().coerceIn(0, 100)
  val reasons = risk.reasonResourceIds.map(context::getString).toMutableList()
  if (deviceIntegrity.isUntrusted) reasons += deviceIntegrity.reasons
  val debugSigned = isDebugSigned(info)
  if (debugSigned) reasons += context.getString(R.string.debug_certificate)
  val apk = appInfo.sourceDir?.let(::File)
  if (apk == null || !apk.isFile || !apk.canRead()) {
   reasons += context.getString(R.string.apk_unreadable)
   val failed = result(info.packageName, label, null, null, if (adjustedRiskScore >= 45) ScanVerdict.SUSPICIOUS else ScanVerdict.NOT_SCANNED, reasons, start).copy(
    packageName = info.packageName,
    scanSessionId = scanSessionId,
    detectionSource = if (adjustedRiskScore >= 45) DetectionSource.HEURISTIC else DetectionSource.NONE
   )
   auditSafely(failed, start, scanSessionId)
   return failed
  }
  val hashes = runCatching { calculator.calculate(apk) }.getOrNull()
   ?: run {
    val failed = result(info.packageName, label, null, null, ScanVerdict.NOT_SCANNED, reasons + context.getString(R.string.file_could_not_read), start).copy(packageName = info.packageName, scanSessionId = scanSessionId)
    auditSafely(failed, start, scanSessionId)
    return failed
   }
  // The hash engine must run before expensive DEX/YARA/ML work. Preserve the
  // existing signed DB, local DB and optional feed ordering and threat evidence.
  val exactThreat = findExactHashThreat(info.packageName, label,
   hashes.sha256, hashes.md5, hashes.sha1, hashes.bytesRead)
  if (exactThreat != null) {
   // Exact hash matches remain an immediate short-circuit: no YARA or ML work runs.
   val evaluated = evaluateWithEnsemble(exactThreat)
   audit(evaluated, start, scanSessionId)
   return evaluated.copy(durationMs = elapsed(start),
    packageName = info.packageName, scanSessionId = scanSessionId)
  }

  val yaraXResult = yaraXScanner.scanApk(apk)
  val yaraThreat = yaraXResult.threatMatches.firstOrNull()
  if (yaraThreat != null) {
   val detected = evaluateWithEnsemble(
    yaraThreatResult(
     info.packageName, label, hashes.sha256, hashes.md5,
     yaraThreat, start, info.packageName, scanSessionId
    ),
    yaraXResult
   )
   audit(detected, start, scanSessionId)
   return detected.copy(
    durationMs = elapsed(start),
    packageName = info.packageName,
    scanSessionId = scanSessionId
   )
  }

  val mlProbability = runMachineLearning(apk)
  val baseDeepReport = deepStaticAnalyzer.analyze(info, apk, debugSigned)
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
  output = evaluateWithEnsemble(output, yaraXResult)
  output = markIncompleteYaraIfOtherwiseClean(output, yaraXResult)
  audit(output, start, scanSessionId)
  return output.copy(durationMs = elapsed(start), packageName = info.packageName, scanSessionId = scanSessionId)
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
    packageName = name, scanSessionId = session, trustedByUser = true)
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
 private suspend fun auditSafely(result: ScanResult, start: Long, scanSessionId: String) {
  try {
   audit(result, start, scanSessionId)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (_: Exception) {
   // A diagnostic-row failure must not turn an inaccessible file into a clean verdict.
  }
 }
 private suspend fun audit(result: ScanResult, start: Long, scanSessionId: String) {
  dao.insertAudit(ScanAudit(
   packageOrPath=hashStore.protectPrivateText(result.packageOrPath.take(250), "scan-label"),
   hash=result.sha256?.let(hashStore::protectHash).orEmpty(),
   scanTimestamp=System.currentTimeMillis(),
   verdict=result.verdict.name,
   scanDuration=elapsed(start),
   scanSessionId=scanSessionId,
    threatEventId=result.threatEventId.orEmpty()
  ))
 }
 private fun revealMetadataOrPlaintext(value: String, purpose: String): String =
  runCatching { hashStore.revealMetadata(value, purpose) }.getOrDefault(value)

 private val trustedSignerDigests: Set<String> by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
  loadTrustedSignerDigests()
 }

 /** Trust is based on certificate equality with the installed Play Services/Play Store signers. */
 private fun isSignedByKnownTrustedCertificate(info: PackageInfo): Boolean {
  val trusted = trustedSignerDigests
  if (trusted.isEmpty()) return false
  return signingCertificateDigests(info).any { it in trusted }
 }

 private fun loadTrustedSignerDigests(): Set<String> =
  TRUSTED_CERTIFICATE_ANCHOR_PACKAGES.flatMap { packageName ->
   val anchor = try {
    pm.getPackageInfo(packageName, signingFlags())
   } catch (_: Exception) {
    null
   }
   anchor?.let(::signingCertificateDigests).orEmpty()
  }.toSet()

 private fun signingCertificateDigests(info: PackageInfo): Set<String> {
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
   runCatching {
    MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
     .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
   }.getOrNull()
  }.toSet()
 }

 private fun isDebugSigned(info: PackageInfo): Boolean = runCatching {
  val signatureBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
   info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
  } else {
   @Suppress("DEPRECATION")
   info.signatures?.firstOrNull()?.toByteArray()
  } ?: return false
  val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(signatureBytes)) as X509Certificate
  val subject = cert.subjectX500Principal.name
  subject.contains("CN=Android Debug", true) || subject.contains("CN=AndroidDebug", true)
 }.getOrDefault(false)
 private fun signingFlags(): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else {
  @Suppress("DEPRECATION")
  PackageManager.GET_SIGNATURES
 }
 private fun result(key: String, label: String, sha: String?, md5: String?, verdict: ScanVerdict, reasons: List<String>, start: Long) =
  ScanResult(key, label, sha, md5, verdict, reasons, elapsed(start), reasonTexts = SecurityText.reasons(context, reasons))
 private fun elapsed(start: Long) = ((System.nanoTime() - start) / 1_000_000L).coerceAtLeast(0)
}

