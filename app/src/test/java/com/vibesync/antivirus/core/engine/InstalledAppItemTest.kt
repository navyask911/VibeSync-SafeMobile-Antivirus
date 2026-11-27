package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class InstalledAppItemTest {
    @Test
    fun inventoryOnlyRecordIsNotMisreportedAsAScanVerdict() {
        val item = InstalledAppItem(
            packageName = "com.example.thirdparty",
            appLabel = "Third-party app"
        )
        assertEquals(InstalledAppItem.INVENTORY_ONLY, item.verdict)
        assertEquals(false, item.verdict == ScanVerdict.NOT_SCANNED.name)
    }
}
