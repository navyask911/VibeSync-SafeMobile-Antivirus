package com.vibesync.antivirus.presentation
import android.content.pm.ApplicationInfo
import org.junit.Assert.*
import org.junit.Test
class SystemPackageGuardTest{
 @Test fun systemFlagsAreProtected(){assertTrue(SystemPackageGuard.isSystemFlags(ApplicationInfo.FLAG_SYSTEM));assertTrue(SystemPackageGuard.isSystemFlags(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))}
 @Test fun userAppFlagsAreNotSystem(){assertFalse(SystemPackageGuard.isSystemFlags(0));assertFalse(SystemPackageGuard.isSystemFlags(ApplicationInfo.FLAG_HAS_CODE))}
 @Test fun packageNamesAreValidated(){assertEquals("com.example.userapp",SystemPackageGuard.normalizePackageName(" com.example.userapp "));assertNull(SystemPackageGuard.normalizePackageName("com.example..bad"));assertNull(SystemPackageGuard.normalizePackageName("invalid package"))}
}
