package com.vibesync.antivirus.core.billing

import org.junit.Assert.assertEquals
import org.junit.Test

class SafeMobileBillingConfigurationTest {
    @Test
    fun activePlaySubscriptionUsesTheConfiguredOneYearPrepaidPlan() {
        assertEquals("safemobile-pro-1y-subs", SafeMobileBillingManager.PRODUCT_ID)
        assertEquals("prepaid-1-year", SafeMobileBillingManager.PREPAID_BASE_PLAN_ID)
        assertEquals("P1Y", SafeMobileBillingManager.PREPAID_BILLING_PERIOD)
    }
}
