package com.vibesync.antivirus.core.engine
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.core.hashdb.HashDatabaseManager
import com.vibesync.antivirus.core.engine.DeepStaticAnalyzer
import com.vibesync.antivirus.core.heuristics.PermissionRiskAnalyzer
import com.vibesync.antivirus.core.security.IntegrityChecker
import com.vibesync.antivirus.core.security.ProtectedPackagePolicy
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.core.security.TrustedAppStore
import kotlin.math.roundToInt
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ThreatDao
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

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
 private val integrityChecker = IntegrityChecker(context)
 private val trustedAppStore = TrustedAppStore(context)
 private val deepStaticAnalyzer = DeepStaticAnalyzer()
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
 suspend fun scanInstalledApps(progress: suspend (processed: Int, total: Int) -> Unit = { _, _ -> }): List<ScanResult> {
  val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or signingFlags()
  val packages = pm.getInstalledPackages(flags).filter { info ->
   val appInfo = info.applicationInfo
   appInfo != null && ProtectedPackagePolicy.isUserInstalled(appInfo.flags, info.packageName, context.packageName)
  }
  val scanSessionId = UUID.randomUUID().toString()
  val results = mutableListOf<ScanResult>()
  progress(0, packages.size)
  for ((index, info) in packages.withIndex()) {
   currentCoroutineContext().ensureActive()
   val packageStart = System.nanoTime()
   val scanned = try {
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
   results += scanned
   progress(index + 1, packages.size)
  }
  return results.sortedBy { when (it.verdict) {
   ScanVerdict.THREAT -> 0
   ScanVerdict.SUSPICIOUS -> 1
   ScanVerdict.NOT_SCANNED -> 2
   ScanVerdict.NO_MATCH -> 3
  } }
 }
 suspend fun scanInstalledPackage(name: String): ScanResult? {
  if (trustedAppStore.isTrusted(name)) return trustedResult(name, UUID.randomUUID().toString(), System.nanoTime())
  if (TrustedPackageWhitelist.hasProtectedNamespace(name)) return null
  val scanSessionId = UUID.randomUUID().toString()
  val info = try {
   pm.getPackageInfo(name, PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingFlags())
  } catch (_: PackageManager.NameNotFoundException) {
   return null
  } catch (_: SecurityException) {
   return result(name, name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.package_metadata_missing)), System.nanoTime()).copy(packageName = name, scanSessionId = scanSessionId)
  }
  val appInfo = info.applicationInfo ?: return null
  if (!ProtectedPackagePolicy.isUserInstalled(appInfo.flags, info.packageName, context.packageName)) return null
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
   val identity = if (file.extension.equals("apk", ignoreCase = true))
    pm.getPackageArchiveInfo(file.absolutePath, 0)?.packageName else null
   if (identity != null && trustedAppStore.isTrusted(identity)) {
    return trustedResult(identity, scanSessionId, start).copy(sourceLocalPath = file.absolutePath)
   }
   val hash = calculator.calculate(file)
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
    deepStaticAnalyzer.analyze(archiveInfo, file, archiveInfo?.let(::isDebugSigned) == true)
   } else null
   val staticReasons = staticReport?.findings.orEmpty().map { "[${it.ruleId}] ${it.evidence} (confidence ${it.confidence}%)" }
   val staticScore = staticReport?.riskScore ?: 0
   val output = evaluate(file.name, file.name, hash.sha256, hash.md5, staticReasons, staticScore, sha1 = hash.sha1, fileSize = hash.bytesRead)
    .copy(riskReport = staticReport)
   if (persistAllAudit || output.verdict == ScanVerdict.THREAT || output.verdict == ScanVerdict.SUSPICIOUS) audit(output, start, scanSessionId)
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
   if (label.substringBefore('?').endsWith(".apk", ignoreCase = true)) {
    // A content URI does not expose package identity. Stage APK bytes in app-private
    // cache so PackageManager can read the manifest before any detection engine.
    val staged = File.createTempFile("trust-identity-", ".apk", context.cacheDir)
    try {
     stream.use { input -> staged.outputStream().use { output ->
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
   val hash = stream.use { calculator.calculate(it) }
   val output = evaluate(label, label, hash.sha256, hash.md5, emptyList(), 0, sha1 = hash.sha1, fileSize = hash.bytesRead)
   if (persistAudit || output.verdict == ScanVerdict.THREAT ||
       output.verdict == ScanVerdict.SUSPICIOUS || output.verdict == ScanVerdict.NOT_SCANNED) {
    audit(output, start, scanSessionId)
   }
   output.copy(durationMs = elapsed(start), scanSessionId = scanSessionId)
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (_: Exception) {
   result(label, label, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_stream_failed)), start).copy(scanSessionId = scanSessionId).also { auditSafely(it, start, scanSessionId) }
  }
 }
 private suspend fun scanPackage(info: PackageInfo, scanSessionId: String): ScanResult {
  val start = System.nanoTime()
  if (trustedAppStore.isTrusted(info.packageName)) return trustedResult(info.packageName, scanSessionId, start)
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
   val failed = result(info.packageName, label, null, null, if (adjustedRiskScore >= 45) ScanVerdict.SUSPICIOUS else ScanVerdict.NOT_SCANNED, reasons, start).copy(packageName = info.packageName, scanSessionId = scanSessionId)
   auditSafely(failed, start, scanSessionId)
   return failed
  }
  val hashes = runCatching { calculator.calculate(apk) }.getOrNull()
   ?: run {
    val failed = result(info.packageName, label, null, null, ScanVerdict.NOT_SCANNED, reasons + context.getString(R.string.file_could_not_read), start).copy(packageName = info.packageName, scanSessionId = scanSessionId)
    auditSafely(failed, start, scanSessionId)
    return failed
   }
  val deepReport = deepStaticAnalyzer.analyze(info, apk, debugSigned)
  val deepReasons = deepReport.findings.map { "[${it.ruleId}] ${it.evidence} (confidence ${it.confidence}%)" }
  reasons += deepReasons
  val combinedRiskScore = maxOf(adjustedRiskScore, deepReport.riskScore)
  val assessed = evaluate(info.packageName, label, hashes.sha256, hashes.md5, reasons, combinedRiskScore, sha1 = hashes.sha1, fileSize = hashes.bytesRead)
   .copy(riskReport = deepReport)
  val output = assessed
  audit(output, start, scanSessionId)
  return output.copy(durationMs = elapsed(start), packageName = info.packageName, scanSessionId = scanSessionId)
 }
 private fun trustedResult(name: String, session: String, start: Long) =
  result(name, name, null, null, ScanVerdict.NO_MATCH,
   listOf(context.getString(R.string.trusted_app_explanation)), start).copy(
    packageName = name, scanSessionId = session, trustedByUser = true)
 private suspend fun evaluate(key: String, label: String, sha: String, md5: String, heuristic: List<String>, score: Int, sha1: String? = null, fileSize: Long? = null): ScanResult {
  val encrypted = hashStore.protectHash(sha)
  val signedHashMatch = hashDatabaseManager?.lookup(sha, md5, sha1, fileSize)
  if (signedHashMatch != null) {
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT,
    listOf(context.getString(R.string.hashdb_match, signedHashMatch.algorithm.token.uppercase(), signedHashMatch.threatName)), 0)
    .copy(threatEventId = UUID.randomUUID().toString(), riskScore = 1f, sha1 = sha1)
  }
  val threat = dao.findThreatByEncryptedHash(encrypted)
  if (threat != null) {
   val family = revealMetadataOrPlaintext(threat.malwareFamily, "family")
   val level = revealMetadataOrPlaintext(threat.threatLevel, "level")
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT, listOf(context.getString(R.string.hash_match, family, level)), 0).copy(threatEventId = UUID.randomUUID().toString(), riskScore = 1f, sha1 = sha1)
  }
  val feedThreat = threatIntelligenceRepository?.lookupHash(sha, md5, sha1, fileSize)
  if (feedThreat != null) {
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT,
    listOf(context.getString(R.string.threat_feed_hash_match, feedThreat.threatName, feedThreat.source)), 0)
    .copy(threatEventId = UUID.randomUUID().toString(), riskScore = 1f, sha1 = sha1)
  }
  // An allow/dismiss choice can suppress heuristics, never an exact known-malware match.
  if (dao.isHashWhitelisted(encrypted)) return ScanResult(key, label, sha, md5, ScanVerdict.NO_MATCH, listOf(context.getString(R.string.hash_allowlisted)), 0).copy(sha1 = sha1)
  val verdict = if (score >= 45) ScanVerdict.SUSPICIOUS else ScanVerdict.NO_MATCH
  val notes = if (heuristic.isEmpty()) listOf(context.getString(R.string.no_match_detail)) else heuristic + context.getString(R.string.risk_review)
  return ScanResult(key, label, sha, md5, verdict, notes, 0).copy(riskScore = score.coerceIn(0, 100) / 100f, sha1 = sha1)
 }
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
  ScanResult(key, label, sha, md5, verdict, reasons, elapsed(start))
 private fun elapsed(start: Long) = ((System.nanoTime() - start) / 1_000_000L).coerceAtLeast(0)
}

