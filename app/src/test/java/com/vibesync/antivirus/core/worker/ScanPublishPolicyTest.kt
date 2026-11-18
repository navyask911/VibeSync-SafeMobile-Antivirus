package com.vibesync.antivirus.core.worker

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanPublishPolicyTest {
 @Test fun zeroPersistedResultsMustFail() {
  assertTrue(ScanPublishPolicy.shouldFail(scannedItems = 0, publishFailures = 0))
 }

 @Test fun anyPublishFailureMustFailEvenWhenSomeItemsPersisted() {
  assertTrue(ScanPublishPolicy.shouldFail(scannedItems = 12, publishFailures = 1))
 }

 @Test fun persistedResultsWithoutPublishFailuresMaySucceed() {
  assertFalse(ScanPublishPolicy.shouldFail(scannedItems = 12, publishFailures = 0))
 }
}
