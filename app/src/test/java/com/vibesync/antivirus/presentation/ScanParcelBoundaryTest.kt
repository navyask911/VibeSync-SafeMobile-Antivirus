package com.vibesync.antivirus.presentation

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.Bitmap
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.os.Parcelable
import com.vibesync.antivirus.core.engine.InstalledAppItem
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.data.local.AppScanCache
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ScanSessionEntity
import com.vibesync.antivirus.data.local.ScanSessionItemEntity
import com.vibesync.antivirus.data.local.ScanSessionState
import java.io.Serializable
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanParcelBoundaryTest {
    private val forbiddenTypes = setOf(
        PackageInfo::class.java,
        ApplicationInfo::class.java,
        Drawable::class.java,
        Bitmap::class.java,
        Bundle::class.java,
        Parcelable::class.java,
        Serializable::class.java
    )

    @Test
    fun installedPackageUiModelContainsExactlyFiveScalarFields() {
        val actual = InstalledAppItem::class.java.declaredFields
            .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
            .associate { it.name to it.type }

        assertEquals(
            mapOf(
                "packageName" to String::class.java,
                "appLabel" to String::class.java,
                "verdict" to String::class.java,
                "fileSize" to java.lang.Long.TYPE,
                "isSystem" to java.lang.Boolean.TYPE
            ),
            actual
        )
    }

    @Test
    fun publishedViewModelsAndScanResultsDoNotContainAndroidParcelables() {
        listOf(
            SafeMobileUiState::class.java,
            ScanResult::class.java,
            InstalledAppItem::class.java
        ).forEach { model ->
            model.declaredFields
                .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
                .forEach { field ->
                    assertFalse(
                        "${model.simpleName}.${field.name} must not hold ${field.type.name}",
                        forbiddenTypes.contains(field.type)
                    )
                }
        }
    }

    @Test
    fun scanRoomEntitiesContainOnlyScalarColumnTypes() {
        val scalarTypes = setOf(
            String::class.java,
            java.lang.Integer.TYPE,
            java.lang.Integer::class.java,
            java.lang.Long.TYPE,
            java.lang.Long::class.java,
            java.lang.Boolean.TYPE,
            java.lang.Boolean::class.java,
            java.lang.Float.TYPE,
            java.lang.Float::class.java,
            java.lang.Double.TYPE,
            java.lang.Double::class.java
        )
        val entities = listOf(
            ScanSessionItemEntity::class.java,
            ScanAudit::class.java,
            ScanSessionEntity::class.java,
            ScanSessionState::class.java,
            AppScanCache::class.java
        )

        entities.forEach { entity ->
            entity.declaredFields
                .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
                .forEach { field ->
                    assertTrue(
                        "${entity.simpleName}.${field.name} has non-scalar Room type ${field.type.name}",
                        scalarTypes.contains(field.type)
                    )
                    assertFalse(
                        "${entity.simpleName}.${field.name} must not be Parcelable/Serializable",
                        forbiddenTypes.contains(field.type)
                    )
                }
        }
    }
}
