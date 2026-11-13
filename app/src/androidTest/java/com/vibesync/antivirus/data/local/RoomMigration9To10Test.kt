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
class RoomMigration9To10Test {
    @Test
    fun migrationCreatesScanSessionsAndPreservesExistingScanAudits() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val callback = object : SupportSQLiteOpenHelper.Callback(9) {
            override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE scan_audits (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "package_or_path TEXT NOT NULL, hash TEXT NOT NULL, " +
                        "scan_timestamp INTEGER NOT NULL, verdict TEXT NOT NULL, " +
                        "scan_duration INTEGER NOT NULL, scan_session_id TEXT NOT NULL DEFAULT '', " +
                        "threat_event_id TEXT NOT NULL DEFAULT '')"
                )
                db.execSQL(
                    "INSERT INTO scan_audits (package_or_path,hash,scan_timestamp,verdict,scan_duration,scan_session_id,threat_event_id) " +
                        "VALUES ('legacy-app','abc',100,'NO_MATCH',10,'legacy-session','')"
                )
            }

            override fun onUpgrade(
                db: androidx.sqlite.db.SupportSQLiteDatabase,
                oldVersion: Int,
                newVersion: Int
            ) = Unit
        }
        val helper = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name("safemobile-migration-9-10-test.db")
                .callback(callback)
                .build()
        )
        try {
            val db = helper.writableDatabase
            ThreatDatabase.MIGRATION_9_10.migrate(db)

            val columns = db.query("PRAGMA table_info(scan_sessions)").use { cursor ->
                buildSet {
                    while (cursor.moveToNext()) {
                        add(cursor.getString(cursor.getColumnIndexOrThrow("name")))
                    }
                }
            }
            assertTrue(columns.contains("session_id"))
            assertTrue(columns.contains("status"))
            assertTrue(columns.contains("started_at"))
            assertTrue(columns.contains("completed_at"))
            assertTrue(columns.contains("scan_type"))

            db.query("SELECT scan_type, status FROM scan_sessions WHERE session_id='legacy-session'").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("LEGACY", cursor.getString(0))
                assertEquals("COMPLETED", cursor.getString(1))
            }

            db.execSQL(
                "INSERT INTO scan_sessions(session_id,scan_type,started_at,completed_at,status) " +
                    "VALUES ('session-1','MANUAL',200,NULL,'IN_PROGRESS')"
            )
            db.execSQL(
                "UPDATE scan_sessions SET status = 'INTERRUPTED' WHERE status = 'IN_PROGRESS'"
            )
            db.query("SELECT status FROM scan_sessions WHERE session_id='session-1'").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("INTERRUPTED", cursor.getString(0))
            }
            db.query("SELECT scan_session_id FROM scan_audits WHERE id=1").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("legacy-session", cursor.getString(0))
            }
        } finally {
            helper.close()
            context.deleteDatabase("safemobile-migration-9-10-test.db")
        }
    }
}
