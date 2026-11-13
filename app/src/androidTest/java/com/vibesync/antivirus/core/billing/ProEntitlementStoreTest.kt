package com.vibesync.antivirus.core.billing

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/** Real encrypted storage, isolated from application entitlements. No Google account or purchase. */
class ProEntitlementStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private lateinit var name: String
    private lateinit var store: ProEntitlementStore

    @Before fun createLedger() {
        name = "pro-ledger-test-${System.nanoTime()}"
        store = ProEntitlementStore(context, name)
    }

    @After fun removeLedger() { context.deleteSharedPreferences(name) }

    @Test fun onePrepaidPurchaseGrantsOneYearAndRepeatedTokenIsIdempotent() {
        val purchaseTime = System.currentTimeMillis()
        assertTrue(store.grantPrepaidSubscription("prepaid-token-one", purchaseTime, purchaseTime))
        val expected = purchaseTime + ProEntitlementStore.MILLIS_PER_YEAR +
            ProEntitlementStore.GOOGLE_GRACE_BUFFER_MS
        assertEquals(expected, store.expiresAt(purchaseTime))
        assertTrue(store.grantPrepaidSubscription("prepaid-token-one", purchaseTime, purchaseTime + 1_000))
        assertEquals(expected, store.expiresAt(purchaseTime + 1_000))
    }

    @Test fun aSecondPrepaidTopUpAddsOneYearToTheExistingExpiry() {
        val purchaseTime = System.currentTimeMillis()
        assertTrue(store.grantPrepaidSubscription("prepaid-token-one", purchaseTime, purchaseTime))
        val firstExpiry = purchaseTime + ProEntitlementStore.MILLIS_PER_YEAR +
            ProEntitlementStore.GOOGLE_GRACE_BUFFER_MS
        val topUpTime = purchaseTime + 30L * 24 * 60 * 60 * 1000
        assertTrue(store.grantPrepaidSubscription("prepaid-token-two", topUpTime, topUpTime))
        val expected = firstExpiry + ProEntitlementStore.MILLIS_PER_YEAR +
            ProEntitlementStore.GOOGLE_GRACE_BUFFER_MS
        assertEquals(expected, store.expiresAt(topUpTime))
    }

    @Test fun invalidPrepaidPurchasesNeverGrantAccess() {
        assertFalse(store.checkProStatusForThisDevice())
        assertFalse(store.grantPrepaidSubscription("", System.currentTimeMillis()))
        assertFalse(store.grantPrepaidSubscription("zero-time", 0L))
        assertFalse(store.grantPrepaidSubscription("negative-time", -1L))
        assertEquals(0L, store.expiresAt())
    }

    @Test fun mismatchClearsDeviceBoundEntitlement() {
        val now = System.currentTimeMillis()
        assertTrue(store.grantPrepaidSubscription("prepaid-token", now, now))
        assertTrue(store.checkProStatusForThisDevice(now))
        assertTrue(store.clearForDeviceMismatch())
        assertFalse(store.checkProStatusForThisDevice(now))
        assertEquals(0L, store.expiresAt(now))
    }

    @Test fun clearedLocalDataCannotBeRecoveredWithoutAPlayRestore() {
        assertTrue(store.grantPrepaidSubscription("prepaid-token", System.currentTimeMillis()))
        assertTrue(ProEntitlementStore(context, name).checkProStatusForThisDevice())
        assertTrue(context.deleteSharedPreferences(name))
        assertFalse(ProEntitlementStore(context, name).checkProStatusForThisDevice())
    }

    @Test fun expiredPrepaidAccessAndClockRollbackFailClosed() {
        val now = System.currentTimeMillis()
        val oldPurchase = now - 2 * ProEntitlementStore.MILLIS_PER_YEAR
        assertTrue(store.grantPrepaidSubscription("old-prepaid-token", oldPurchase, now))
        assertFalse(store.checkProStatusForThisDevice(now))
        assertFalse(store.checkProStatusForThisDevice(now - 6 * 60 * 1000))
    }
}
