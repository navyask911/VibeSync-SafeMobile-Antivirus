package com.vibesync.antivirus.presentation
import android.content.pm.ApplicationInfo
import org.junit.Assert.*
import org.junit.Test
class SystemPackageGuardTest {
 @Test fun systemFlagsReturnBlocked() {
  assertTrue(SystemPackageGuard.evaluateFlags(ApplicationInfo.FLAG_SYSTEM) is PackageGuardResult.BlockedSystemApp)
  assertTrue(SystemPackageGuard.evaluateFlags(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) is PackageGuardResult.BlockedSystemApp)
 }
 @Test fun normalUserAppReturnsAllowed() {
  assertEquals(PackageGuardResult.Allowed,SystemPackageGuard.evaluateFlags(ApplicationInfo.FLAG_HAS_CODE))
  assertEquals(PackageGuardResult.Allowed,SystemPackageGuard.evaluateFlags(0))
 }
 @Test fun deviceAdminIsBlocked() {
  assertTrue(SystemPackageGuard.evaluateFlags(0,isActiveDeviceAdmin=true) is PackageGuardResult.BlockedSystemApp)
 }
 @Test fun validatesPackageNames() {
  assertEquals("com.example.userapp",SystemPackageGuard.normalizePackageName(" com.example.userapp "))
  assertNull(SystemPackageGuard.normalizePackageName("com.example..bad"))
  assertNull(SystemPackageGuard.normalizePackageName("bad package"))
 }
}
