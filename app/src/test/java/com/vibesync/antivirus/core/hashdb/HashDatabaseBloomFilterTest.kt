package com.vibesync.antivirus.core.hashdb

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HashDatabaseBloomFilterTest {
    @Test fun insertedValuesAlwaysPassPrefilterAndDistinctValueUsuallyDoesNot() {
        val rows = listOf(
            HashDatabaseRecord(HashAlgorithm.MD5, "44d88612fea8a8f36de82e1278abb02f", "test"),
            HashDatabaseRecord(HashAlgorithm.SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "test")
        )
        val filter = HashDatabaseBloomFilter.fromRecords(rows)
        rows.forEach { assertTrue(filter.mightContain(it.bloomKey)) }
        assertFalse(filter.mightContain("sha256:" + "0".repeat(64)))
    }

    @Test fun rejectsImpossibleCapacity() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            HashDatabaseBloomFilter.create(HashDatabaseFormat.MAX_RECORDS + 1)
        }
    }
}
