package com.vibesync.antivirus.core.observer

import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** CI pushes its locally built no-code fixture; no malware or external download is used. */
@RunWith(AndroidJUnit4::class)
class BackgroundInstallSirenTest {
    private val fixture = "/data/local/tmp/SafeMobile-Siren-Test.apk"
    private fun shell(command: String): String = InstrumentationRegistry.getInstrumentation().uiAutomation
        .executeShellCommand(command).use { descriptor ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
        }

    private fun await(timeout: Long, condition: () -> Boolean) {
        val until = SystemClock.elapsedRealtime() + timeout
        while (!condition() && SystemClock.elapsedRealtime() < until) Thread.sleep(25)
        assertTrue("Expected condition before timeout", condition())
    }

    @Test fun systemInstallWhileActivityIsBackgroundedTriggersBoundedDiagnosticAlarmWithoutHashImport() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("sirenFixturePath") == fixture)
        val context = ApplicationProvider.getApplicationContext<Context>()
        val privacy = context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
        val security = context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
        val oldPrivacy = privacy.getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)
        val oldEnabled = security.getBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true)
        val onboarding = context.getSharedPreferences(com.vibesync.antivirus.presentation.OnboardingPrefs.NAME, Context.MODE_PRIVATE)
        val oldAutoScan = onboarding.getBoolean(com.vibesync.antivirus.presentation.OnboardingPrefs.FIRST_SCAN_REQUESTED, false)
        onboarding.edit().putBoolean(com.vibesync.antivirus.presentation.OnboardingPrefs.FIRST_SCAN_REQUESTED, true).commit()
        privacy.edit().putBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, true).commit()
        security.edit().putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true).commit()
        if (Build.VERSION.SDK_INT >= 33) shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
        runBlocking { com.vibesync.antivirus.core.security.TrustedAppStore(context).untrust(InstallDiagnosticPolicy.FIXTURE_PACKAGE) }
        shell("pm uninstall com.safemobile.sirentest")
        try {
            ActivityScenario.launch(MainActivity::class.java).use { activity ->
                await(10_000) { InstallSentinelService.running.value }
                activity.onActivity { it.moveTaskToBack(true) }
                val result = shell("pm install -r $fixture")
                assertTrue(result, result.contains("Success"))
                await(10_000) { SecurityIncidentSiren.playing }
                val manager = context.getSystemService(NotificationManager::class.java)
                await(5_000) { manager.activeNotifications.any {
                    it.notification.channelId == SecurityAlertNotifier.CHANNEL_ID &&
                        it.notification.extras.getCharSequence("android.title").toString() == context.getString(R.string.siren_test_title)
                } }
                await(7_000) { !SecurityIncidentSiren.playing }
            }
        } finally {
            SecurityAlertNotifier.stopIncidentAudio()
            InstallSentinelService.stop(context)
            shell("pm uninstall com.safemobile.sirentest")
            privacy.edit().putBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, oldPrivacy).commit()
            security.edit().putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, oldEnabled).commit()
            onboarding.edit().putBoolean(com.vibesync.antivirus.presentation.OnboardingPrefs.FIRST_SCAN_REQUESTED, oldAutoScan).commit()
        }
    }
}
