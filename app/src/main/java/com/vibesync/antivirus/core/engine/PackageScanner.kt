package com.vibesync.antivirus.core.engine
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.core.heuristics.PermissionRiskAnalyzer
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ThreatDao
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class PackageScanner(
 private val context: Context,
 private val dao: ThreatDao,
 private val hashStore: EncryptedHashStore,
 private val calculator: HashCalculator = HashCalculator(),
 private val riskAnalyzer: PermissionRiskAnalyzer = PermissionRiskAnalyzer()
) {
 private val pm = context.packageManager
 suspend fun scanInstalledApps(): List<ScanResult> {
  val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingFlags()
  val results = mutableListOf<ScanResult>()
  for (info in pm.getInstalledPackages(flags)) {
   val scanned = runCatching { scanPackage(info) }.getOrNull()
   if (scanned != null) results += scanned
  }
  return results.sortedBy { when (it.verdict) {
   ScanVerdict.THREAT -> 0
   ScanVerdict.SUSPICIOUS -> 1
   ScanVerdict.NOT_SCANNED -> 2
   ScanVerdict.NO_MATCH -> 3
  } }
 }
 suspend fun scanInstalledPackage(name: String): ScanResult? {
  val info = runCatching { pm.getPackageInfo(name, PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or signingFlags()) }.getOrNull()
  return if (info == null) null else scanPackage(info)
 }
 suspend fun scanFile(file: File): ScanResult {
  val start = System.nanoTime()
  if (!file.isFile || !file.canRead()) return result(file.name, file.name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_not_readable)), start)
  return runCatching {
   val hash = calculator.calculate(file)
   val output = evaluate(file.name, file.name, hash.sha256, hash.md5, emptyList(), 0, false)
   audit(output, start)
   output.copy(durationMs = elapsed(start))
  }.getOrElse { result(file.name, file.name, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_could_not_read)), start) }
 }
 suspend fun scanStream(label: String, stream: java.io.InputStream): ScanResult {
  val start = System.nanoTime()
  return runCatching {
   val hash = stream.use { calculator.calculate(it) }
   val output = evaluate(label, label, hash.sha256, hash.md5, emptyList(), 0, false)
   audit(output, start)
   output.copy(durationMs = elapsed(start))
  }.getOrElse { result(label, label, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_stream_failed)), start) }
 }
 private suspend fun scanPackage(info: PackageInfo): ScanResult {
  val start = System.nanoTime()
  val appInfo = info.applicationInfo ?: return result(info.packageName, info.packageName, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.package_metadata_missing)), start)
  val label = appInfo.loadLabel(pm).toString()
  val permissions = info.requestedPermissions?.toSet().orEmpty()
  val accessibility = info.services.orEmpty().any { it.permission == PermissionRiskAnalyzer.BIND_ACCESSIBILITY }
  val risk = riskAnalyzer.assess(permissions, accessibility)
  val reasons = risk.reasonResourceIds.map(context::getString).toMutableList()
  val debugSigned = isDebugSigned(info)
  if (debugSigned) reasons += context.getString(R.string.debug_certificate)
  val apk = appInfo.sourceDir?.let(::File)
  if (apk == null || !apk.isFile || !apk.canRead()) {
   reasons += context.getString(R.string.apk_unreadable)
   return result(info.packageName, label, null, null, if (risk.isSuspicious || debugSigned) ScanVerdict.SUSPICIOUS else ScanVerdict.NOT_SCANNED, reasons, start)
  }
  val hashes = runCatching { calculator.calculate(apk) }.getOrNull()
   ?: return result(info.packageName, label, null, null, ScanVerdict.NOT_SCANNED, reasons + context.getString(R.string.file_could_not_read), start)
  val output = evaluate(info.packageName, label, hashes.sha256, hashes.md5, reasons, risk.score, debugSigned)
  audit(output, start)
  return output.copy(durationMs = elapsed(start))
 }
 private suspend fun evaluate(key: String, label: String, sha: String, md5: String, heuristic: List<String>, score: Int, debug: Boolean): ScanResult {
  val encrypted = hashStore.protectHash(sha)
  if (dao.isHashWhitelisted(encrypted)) return ScanResult(key, label, sha, md5, ScanVerdict.NO_MATCH, listOf(context.getString(R.string.hash_allowlisted)), 0)
  val threat = dao.findThreatByEncryptedHash(encrypted)
  if (threat != null) {
   val family = revealMetadataOrPlaintext(threat.malwareFamily, "family")
   val level = revealMetadataOrPlaintext(threat.threatLevel, "level")
   return ScanResult(key, label, sha, md5, ScanVerdict.THREAT, listOf(context.getString(R.string.hash_match, family, level)), 0)
  }
  val verdict = if (score >= 45 || debug) ScanVerdict.SUSPICIOUS else ScanVerdict.NO_MATCH
  val notes = if (heuristic.isEmpty()) listOf(context.getString(R.string.no_match_detail)) else heuristic + context.getString(R.string.risk_review)
  return ScanResult(key, label, sha, md5, verdict, notes, 0)
 }
 private suspend fun audit(result: ScanResult, start: Long) {
  dao.insertAudit(ScanAudit(
   packageOrPath=result.packageOrPath.take(250),
   hash=result.sha256?.let(hashStore::protectHash).orEmpty(),
   scanTimestamp=System.currentTimeMillis(),
   verdict=result.verdict.name,
   scanDuration=elapsed(start)
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
