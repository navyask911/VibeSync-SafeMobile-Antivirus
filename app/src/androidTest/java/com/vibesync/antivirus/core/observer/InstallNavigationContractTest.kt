package com.vibesync.antivirus.core.observer

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.core.posture.PostureAccess
import com.vibesync.antivirus.core.posture.PostureFinding
import com.vibesync.antivirus.core.posture.PostureSettingsLinks
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InstallNavigationContractTest {
    @Test fun packageUrisAlwaysReferToTheInstalledPackageRegardlessOfInstaller() {
        assertEquals("com.example.fixture", PackageInstallReceiver.packageFrom(Uri.parse("package:com.example.fixture")))
        assertEquals("com.example.fixture", PackageInstallReceiver.packageFrom(Uri.parse("package://com.example.fixture")))
        assertNull(PackageInstallReceiver.packageFrom(Uri.parse("content://com.whatsapp/fixture.apk")))
        assertNull(PackageInstallReceiver.packageFrom(Uri.parse("package:invalid-Siren-Test")))
        assertNull(PackageInstallReceiver.packageFrom(null))
    }

    @Test fun accessibilitySettingsCandidatesUseDetailsThenCategoryFallback() {
        for (name in listOf("example.first", "example.second")) {
            val component = "$name/.ExampleAccessibilityService"
            val candidates = PostureSettingsLinks.candidates(
                PostureFinding(PostureAccess.ACCESSIBILITY, name, name, componentName = component)
            )
            assertEquals("android.settings.ACCESSIBILITY_DETAILS_SETTINGS", candidates.first().action)
            assertEquals(Settings.ACTION_ACCESSIBILITY_SETTINGS, candidates[1].action)
        }
    }
}
