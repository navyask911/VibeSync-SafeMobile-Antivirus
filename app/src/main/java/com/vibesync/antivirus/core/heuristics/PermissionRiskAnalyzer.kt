package com.vibesync.antivirus.core.heuristics

data class RiskAssessment(val score: Int, val reasonResourceIds: List<Int>) {
 val isSuspicious: Boolean get() = score >= 45
}

/**
 * Permission clustering is a triage signal, not proof of malware.
 * This class only examines declared permissions and manifest service metadata; it does not read
 * SMS, notifications, accessibility events, screen content, or credentials.
 */
class PermissionRiskAnalyzer {
 fun assess(permissions: Set<String>, hasAccessibilityService: Boolean): RiskAssessment {
  val reasons = mutableListOf<Int>()
  var score = 0
  if (RECEIVE_BOOT in permissions) { score += 10; reasons += com.vibesync.antivirus.R.string.risk_boot }
  if (SYSTEM_ALERT in permissions) { score += 20; reasons += com.vibesync.antivirus.R.string.risk_overlay }
  if (REQUEST_INSTALL in permissions) { score += 20; reasons += com.vibesync.antivirus.R.string.risk_install }
  if (hasAccessibilityService) { score += 20; reasons += com.vibesync.antivirus.R.string.risk_accessibility }

  val canReadSms = READ_SMS in permissions || RECEIVE_SMS in permissions
  if (canReadSms && INTERNET in permissions) {
   score += 20
   reasons += com.vibesync.antivirus.R.string.risk_sms_internet
  }
  if (canReadSms && hasAccessibilityService) {
   score += 25
   reasons += com.vibesync.antivirus.R.string.risk_sms_accessibility
  }

  val cluster = listOf(
   RECEIVE_BOOT in permissions,
   SYSTEM_ALERT in permissions,
   REQUEST_INSTALL in permissions,
   hasAccessibilityService,
   canReadSms && INTERNET in permissions
  ).count { it }
  if (cluster >= 3) { score += 25; reasons += com.vibesync.antivirus.R.string.risk_cluster }
  return RiskAssessment(score.coerceAtMost(100), reasons.distinct())
 }

 companion object {
  const val RECEIVE_BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
  const val SYSTEM_ALERT = "android.permission.SYSTEM_ALERT_WINDOW"
  const val REQUEST_INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES"
  const val READ_SMS = "android.permission.READ_SMS"
  const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
  const val INTERNET = "android.permission.INTERNET"
  const val BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
 }
}
