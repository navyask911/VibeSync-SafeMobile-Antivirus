package com.vibesync.antivirus.core.posture

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.integration.android.SharedPrefKeysetWriter
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DevicePostureIntegrationTest {
    private val context get() = ApplicationProvider.getApplicationContext<Context>()
    private val finding = PostureFinding(PostureAccess.ACCESSIBILITY, "example.reader", "Reader",
        "example.reader/.ReaderService", false)

    @Test fun encryptedStateSurvivesNewStoreInstanceAndUsesFreshCiphertext() {
        val file = File(context.noBackupFilesDir, "posture-test-${UUID.randomUUID()}.bin")
        val capability = PostureCapability(finding.access, finding.packageName)
        val snapshot = PostureSnapshot(PostureSnapshotComparison.monitored, setOf(capability),
            setOf(PostureChange(capability, 100)), 100)
        try {
            val first = EncryptedPostureSnapshotStore(context, file)
            assertNull(first.read())
            first.write(snapshot)
            val encrypted = file.readBytes()
            assertFalse(String(encrypted, Charsets.ISO_8859_1).contains(finding.packageName))
            val reopened = EncryptedPostureSnapshotStore(context, file)
            assertEquals(snapshot, reopened.read())
            reopened.write(snapshot)
            assertFalse(encrypted.contentEquals(file.readBytes()))
            assertEquals(snapshot, reopened.read())
        } finally { deleteFixture(file) }
    }

    @Test fun tamperedCiphertextIsRejectedAndNeverSilentlyReset() {
        val file = File(context.noBackupFilesDir, "posture-test-${UUID.randomUUID()}.bin")
        try {
            val store = EncryptedPostureSnapshotStore(context, file)
            store.write(PostureSnapshot())
            val damaged = file.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            file.writeBytes(damaged)
            try { EncryptedPostureSnapshotStore(context, file).read(); fail("Authenticated ciphertext must be rejected") }
            catch (_: java.security.GeneralSecurityException) { }
            assertArrayEquals(damaged, file.readBytes())
        } finally { deleteFixture(file) }
    }

    @Suppress("DEPRECATION")
    @Test fun cleartextKeysetIsRefusedEvenWithAnAvailableKeystoreMasterKey() {
        val prefs = "posture-test-${UUID.randomUUID()}"
        val file = File(context.noBackupFilesDir, "$prefs.bin")
        try {
            EncryptedPostureSnapshotStore(context, file, prefs).write(PostureSnapshot())
            val encrypted = file.readBytes()
            // Model a legacy/fallback keyset in isolated test preferences, never production keys.
            val unprotected = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"))
            CleartextKeysetHandle.write(unprotected, SharedPrefKeysetWriter(context, "posture_keyset", prefs))
            try {
                EncryptedPostureSnapshotStore(context, file, prefs).write(PostureSnapshot())
                fail("Cleartext keysets must be refused even if isUsingKeystore is true")
            } catch (_: java.security.GeneralSecurityException) { }
            assertArrayEquals(encrypted, file.readBytes())
        } finally {
            context.getSharedPreferences(prefs, Context.MODE_PRIVATE).edit().clear().commit()
            deleteFixture(file)
        }
    }

    @Test fun settingsLinksUseReviewDestinationsAndNeverAnAdministratorActivation() {
        for (access in PostureAccess.entries) {
            val intents = PostureSettingsLinks.candidates(finding.copy(access = access))
            assertTrue(intents.isNotEmpty())
            assertTrue(intents.all { it.action?.startsWith("android.settings.") == true })
            assertFalse(intents.any { it.action == "android.app.action.ADD_DEVICE_ADMIN" || it.action == Intent.ACTION_DELETE })
            assertEquals(Settings.ACTION_SETTINGS, intents.last().action)
        }
        val accessibility = PostureSettingsLinks.candidates(finding).first()
        @Suppress("DEPRECATION")
        val component = accessibility.getParcelableExtra<ComponentName>(Intent.EXTRA_COMPONENT_NAME)
        assertEquals(ComponentName.unflattenFromString(finding.componentName!!), component)
        assertEquals("package:example.reader", PostureSettingsLinks.candidates(finding.copy(access = PostureAccess.OVERLAY)).first().data.toString())
    }

    @Test fun notificationDetailUsesTheStringComponentContractWhenSupported() {
        val intents = PostureSettingsLinks.candidates(finding.copy(access = PostureAccess.NOTIFICATION_LISTENER))
        if (Build.VERSION.SDK_INT >= 30) {
            assertEquals(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS, intents.first().action)
            assertEquals(finding.componentName, intents.first().getStringExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME))
        } else assertEquals(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS, intents.first().action)
    }

    @Test fun inspectorReadsMetadataWithoutNeedingAnySensitiveGrant() {
        val report = DevicePostureInspector(context).inspect()
        assertTrue(report.checkedAt > 0)
        assertEquals(report.findings.size, report.findings.distinctBy { Triple(it.access, it.packageName, it.componentName) }.size)
        assertTrue(report.findings.all { it.packageName.isNotBlank() && it.appName.isNotBlank() })
        assertTrue(report.findings.filter { it.access != PostureAccess.OVERLAY }.all { it.state == PostureGrantState.ENABLED })
        val monitored = DevicePostureInspector(context).inspect(includeOverlay = false)
        assertFalse(monitored.findings.any { it.access == PostureAccess.OVERLAY })
    }

    private fun deleteFixture(file: File) {
        file.delete()
        File(file.path + ".bak").delete()
        File(file.path + ".new").delete()
    }
}
