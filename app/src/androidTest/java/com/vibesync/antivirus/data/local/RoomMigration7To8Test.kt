package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RoomMigration7To8Test {
    @Test fun migrationAddsFeedRollbackStateWithoutDroppingExistingColumns() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val callback = object : SupportSQLiteOpenHelper.Callback(7) {
            override fun onCreate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE threat_feed_sync_state (" +
                        "source_key TEXT NOT NULL PRIMARY KEY, source_host TEXT NOT NULL, " +
                        "last_attempt_at INTEGER NOT NULL, last_success_at INTEGER, status TEXT NOT NULL, " +
                        "last_error TEXT, last_imported_count INTEGER NOT NULL, etag TEXT, last_modified TEXT)"
                )
                db.execSQL("INSERT INTO threat_feed_sync_state (source_key,source_host,last_attempt_at,status,last_imported_count) VALUES ('source','example.test',1,'OK',1)")
            }
            override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
        }
        val helper = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name("safemobile-migration-7-8-test.db")
                .callback(callback)
                .build()
        )
        try {
            val db = helper.writableDatabase
            ThreatDatabase.MIGRATION_7_8.migrate(db)
            val cursor = db.query("PRAGMA table_info(threat_feed_sync_state)")
            val columns = buildSet {
                cursor.use { while (it.moveToNext()) add(it.getString(it.getColumnIndexOrThrow("name"))) }
            }
            assertTrue(columns.contains("source_key"))
            assertTrue(columns.contains("feed_version"))
            assertTrue(columns.contains("feed_manifest_sha256"))
            val existing = db.query("SELECT last_imported_count, feed_version FROM threat_feed_sync_state WHERE source_key='source'")
            existing.use {
                assertTrue(it.moveToFirst())
                assertTrue(it.getInt(it.getColumnIndexOrThrow("last_imported_count")) == 1)
                assertTrue(it.getLong(it.getColumnIndexOrThrow("feed_version")) == 0L)
            }
        } finally {
            helper.close()
            context.deleteDatabase("safemobile-migration-7-8-test.db")
        }
    }
}
