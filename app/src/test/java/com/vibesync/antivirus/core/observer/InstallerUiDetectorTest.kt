package com.vibesync.antivirus.core.observer
import org.junit.Assert.*
import org.junit.Test
class InstallerUiDetectorTest{
 @Test fun detectsApkButNotOtherExecutable(){assertTrue(InstallerUiDetector.isApkInstallUi(listOf("sent.apk")));assertFalse(InstallerUiDetector.isApkInstallUi(listOf("setup.exe","Install this application")))}
 @Test fun extractsSafeFilename(){assertEquals("shared.apk",InstallerUiDetector.extractApkFilename("/storage/emulated/0/Download/shared.apk"));assertNull(InstallerUiDetector.extractApkFilename("script.exe"))}
 @Test fun recognizesInstallerPackage(){assertTrue(InstallerUiDetector.isInstallerPackage("com.google.android.packageinstaller"));assertTrue(InstallerUiDetector.isInstallerPackage("com.samsung.android.packageinstaller"));assertFalse(InstallerUiDetector.isInstallerPackage("com.whatsapp"))}
}
