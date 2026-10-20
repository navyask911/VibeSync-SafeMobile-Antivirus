package com.vibesync.antivirus.core.heuristics
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
class PermissionRiskAnalyzerTest {
 @Test fun ordinaryPermissionSetIsNotSuspicious() {
  assertFalse(PermissionRiskAnalyzer().assess(setOf("android.permission.INTERNET"), false).isSuspicious)
 }
 @Test fun combinedSensitivePermissionsAreFlaggedForReview() {
  val result = PermissionRiskAnalyzer().assess(setOf(
   PermissionRiskAnalyzer.RECEIVE_BOOT, PermissionRiskAnalyzer.SYSTEM_ALERT, PermissionRiskAnalyzer.REQUEST_INSTALL
  ), true)
  assertTrue(result.isSuspicious)
  assertTrue(result.score >= 45)
 }
}
