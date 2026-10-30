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

    @Test fun actualQuantityExtendsExpiryAndRepeatedTokenIsIdempotent() {
        val now = System.currentTimeMillis()
        assertTrue(store.grant("test-purchase-one", 2, now))
        val expected = now + 2 * ProEntitlementStore.MILLIS_PER_YEAR
        assertEquals(expected, store.expiresAt())
        assertTrue(store.grant("test-purchase-one", 2, now + 1_000))
        assertEquals(expected, store.expiresAt())
        assertTrue(store.grant("test-purchase-two", 1, now + 2_000))
        assertEquals(expected + ProEntitlementStore.MILLIS_PER_YEAR, store.expiresAt())
    }

    @Test fun missingDataAndInvalidQuantitiesNeverGrantPro() {
        assertFalse(store.checkProStatusForThisDevice())
        assertFalse(store.grant("", 1))
        assertFalse(store.grant("test-zero", 0))
        assertFalse(store.grant("test-negative", -1))
        assertFalse(store.grant("test-overflow", Int.MAX_VALUE))
        assertEquals(0L, store.expiresAt())
    }

    @Test fun actualPlayQuantityIsNotCappedByThePriceEstimateSelector() {
        val now = System.currentTimeMillis()
        assertTrue(store.grant("test-play-cart-quantity", 11, now))
        assertEquals(now + 11 * ProEntitlementStore.MILLIS_PER_YEAR, store.expiresAt())
    }

    @Test fun clearedLocalDataCannotBeRecoveredByCreatingAnotherLedger() {
        assertTrue(store.grant("test-consumed-purchase", 1))
        assertTrue(ProEntitlementStore(context, name).checkProStatusForThisDevice())
        assertTrue(context.deleteSharedPreferences(name))
        assertFalse(ProEntitlementStore(context, name).checkProStatusForThisDevice())
    }

    @Test fun expiredPassStartsANewPeriodAndClockRollbackFailsClosed() {
        val now = System.currentTimeMillis()
        assertTrue(store.grant("test-expired", 1, now - 2 * ProEntitlementStore.MILLIS_PER_YEAR))
        assertFalse(store.checkProStatusForThisDevice(now))
        assertTrue(store.grant("test-new-period", 1, now))
        assertEquals(now + ProEntitlementStore.MILLIS_PER_YEAR, store.expiresAt())
        assertFalse(store.checkProStatusForThisDevice(now - 6 * 60 * 1000))
    }
}
