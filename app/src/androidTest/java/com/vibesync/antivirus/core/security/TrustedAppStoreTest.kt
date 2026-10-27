package com.vibesync.antivirus.core.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class TrustedAppStoreTest {
    @Test fun exactDigestTrustDoesNotApplyToUpdatedApk() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = TrustedAppStore(context)
        val name = "com.example.safemobiletest." + UUID.randomUUID().toString().replace("-", "")
        val original = "a".repeat(64)
        val updated = "b".repeat(64)
        try {
            assertFalse(store.isTrusted(name, original))
            assertTrue(store.trust(name, original))
            assertTrue(store.isTrusted(name, original))
            assertFalse(store.isTrusted(name, updated))
            assertFalse(store.trust("invalid package", original))
        } finally {
            store.untrust(name, original)
        }
        assertFalse(store.isTrusted(name, original))
    }
}
