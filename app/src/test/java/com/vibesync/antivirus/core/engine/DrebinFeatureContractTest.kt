package com.vibesync.antivirus.core.engine

import org.junit.Assert.*
import org.junit.Test

class DrebinFeatureContractTest {
    private val names = List(215) { "unused_feature_" + it }.toMutableList().apply {
        this[6] = "SEND_SMS"
        this[25] = "android.intent.action.BOOT_COMPLETED"
        this[31] = "DexClassLoader"
        this[51] = "Ljava.lang.Class.forName"
        this[79] = "chmod"
        this[128] = "Runtime.exec"
        this[141] = "/system/bin"
    }

    @Test fun schemaOrderMatchesExactPositionsWithoutNameSubstringMatching() {
        val signals = DrebinFeatureContract.Observed(
            permissions = setOf("android.permission.SEND_SMS", "android.permission.READ_SMS"),
            actions = setOf("android.intent.action.BOOT_COMPLETED"),
            classes = setOf("Ldalvik/system/DexClassLoader;"),
            calls = setOf("Ljava/lang/Class;" to "forName", "Ljava/lang/Runtime;" to "exec"),
            callbacks = emptySet(),
            literals = setOf("chmod /system/bin/fake"))
        val values = DrebinFeatureContract.vector(names, signals)
        assertEquals(215, values.size)
        for (index in listOf(6, 25, 31, 51, 79, 128, 141)) {
            assertEquals("feature index " + index, 1f, values[index])
        }
        assertEquals(0f, values[0])
        assertEquals(0f, values[1])
    }

    @Test fun uninvokedNamesAndPermissionSubstringsDoNotTrigger() {
        val signals = DrebinFeatureContract.Observed(
            permissions = setOf("example.permission.SEND_SMS"),
            actions = setOf("android.intent.action.BOOT_COMPLETED_FAKE"),
            classes = setOf("Ldalvik/system/DexClassLoaderExtra;"),
            calls = setOf("Ljava/lang/Other;" to "forName"),
            callbacks = emptySet(),
            literals = setOf("mischmodification /system/binaries"))
        val v = DrebinFeatureContract.vector(names, signals)
        assertEquals(0f, v[6]); assertEquals(0f, v[25])
        assertEquals(0f, v[31]); assertEquals(0f, v[51])
        assertEquals(0f, v[79]); assertEquals(0f, v[141])
    }

    @Test(expected = IllegalArgumentException::class)
    fun duplicateSchemaIsRejected() {
        DrebinFeatureContract.vector(List(215) { "same" },
            DrebinFeatureContract.Observed(emptySet(),emptySet(),emptySet(),
                emptySet(),emptySet(),emptySet()))
    }
}
