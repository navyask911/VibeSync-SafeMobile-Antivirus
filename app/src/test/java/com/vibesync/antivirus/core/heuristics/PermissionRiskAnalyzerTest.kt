package com.vibesync.antivirus.core.heuristics
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionRiskAnalyzerTest {
 @Test fun ordinaryPermissionSetIsNotSuspicious() {
  assertFalse(PermissionRiskAnalyzer().assess(setOf(PermissionRiskAnalyzer.INTERNET), false).isSuspicious)
 }

 @Test fun combinedSensitivePermissionsAreFlaggedForReview() {
  val result=PermissionRiskAnalyzer().assess(setOf(
   PermissionRiskAnalyzer.RECEIVE_BOOT, PermissionRiskAnalyzer.SYSTEM_ALERT, PermissionRiskAnalyzer.REQUEST_INSTALL
  ), true)
  assertTrue(result.isSuspicious)
  assertTrue(result.score >= 45)
 }

 @Test fun smsAndInternetCombinationIsShownAsRiskIndicator() {
  val result=PermissionRiskAnalyzer().assess(setOf(
   PermissionRiskAnalyzer.READ_SMS, PermissionRiskAnalyzer.INTERNET
  ), false)
  assertTrue(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_sms_internet))
  assertFalse(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_sms_accessibility))
  assertFalse(result.isSuspicious)
 }

 @Test fun smsAndAccessibilityCombinationRaisesReviewScoreWithoutProvingMalware() {
  val result=PermissionRiskAnalyzer().assess(setOf(
   PermissionRiskAnalyzer.RECEIVE_SMS, PermissionRiskAnalyzer.INTERNET
  ), true)
  assertTrue(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_sms_internet))
  assertTrue(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_sms_accessibility))
  assertTrue(result.isSuspicious)
 }
 @Test fun accessibilityAndOverlayAddCompoundRiskReason() {
  val result=PermissionRiskAnalyzer().assess(setOf(PermissionRiskAnalyzer.SYSTEM_ALERT),true)
  assertTrue(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_accessibility_overlay))
  assertTrue(result.score>=80)
 }
 @Test fun bootSmsInternetAddsPersistenceRiskReason() {
  val result=PermissionRiskAnalyzer().assess(setOf(PermissionRiskAnalyzer.RECEIVE_BOOT,PermissionRiskAnalyzer.READ_SMS,PermissionRiskAnalyzer.INTERNET),false)
  assertTrue(result.reasonResourceIds.contains(com.vibesync.antivirus.R.string.risk_boot_sms_internet))
  assertTrue(result.score>=55)
 }

}
