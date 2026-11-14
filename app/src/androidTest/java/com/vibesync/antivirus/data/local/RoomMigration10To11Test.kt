package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RoomMigration10To11Test {
    @Test
    fun migrationCreatesAppScanCacheAndPreservesExistingTables() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val callback = object : SupportSQLiteOpenHelper.Callback(10) {
            override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE scan_audits (id INTEGER PRIMARY KEY NOT NULL, verdict TEXT NOT NULL)")
                db.execSQL("INSERT INTO scan_audits(id, verdict) VALUES (1, 'NO_MATCH')")
            }

            override fun onUpgrade(
                db: androidx.sqlite.db.SupportSQLiteDatabase,
                oldVersion: Int,
                newVersion: Int
            ) = Unit
        }
        val helper = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name("safemobile-migration-10-11-test.db")
                .callback(callback)
                .build()
        )
        try {
            val db = helper.writableDatabase
            ThreatDatabase.MIGRATION_10_11.migrate(db)

            val columns = db.query("PRAGMA table_info(app_scan_cache)").use { cursor ->
                buildMap {
                    while (cursor.moveToNext()) {
                        put(
                            cursor.getString(cursor.getColumnIndexOrThrow("name")),
                            cursor.getInt(cursor.getColumnIndexOrThrow("notnull"))
                        )
                    }
                }
            }
            assertEquals(
                setOf("packageName", "lastUpdateTime", "fileSize", "sha256", "verdict", "threatName"),
                columns.keys
            )
            assertEquals(1, columns["packageName"])
            assertEquals(1, columns["lastUpdateTime"])
            assertEquals(1, columns["fileSize"])
            assertEquals(1, columns["sha256"])
            assertEquals(1, columns["verdict"])
            assertEquals(0, columns["threatName"])

            db.execSQL(
                "INSERT INTO app_scan_cache(packageName,lastUpdateTime,fileSize,sha256,verdict,threatName) " +
                    "VALUES ('com.example.app',1234,4096,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','NO_MATCH',NULL)"
            )
            db.query("SELECT lastUpdateTime,fileSize,verdict,threatName FROM app_scan_cache WHERE packageName='com.example.app'").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals(1234L, cursor.getLong(0))
                assertEquals(4096L, cursor.getLong(1))
                assertEquals("NO_MATCH", cursor.getString(2))
                assertTrue(cursor.isNull(3))
            }
            db.query("SELECT verdict FROM scan_audits WHERE id=1").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("NO_MATCH", cursor.getString(0))
            }
        } finally {
            helper.close()
            context.deleteDatabase("safemobile-migration-10-11-test.db")
        }
    }
}
