package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ThreatDatabaseMigration12To13Test {
    @Test
    fun migrationPreservesVersion12RowsAndAddsBackwardCompatibleDefaults() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val databaseName = "threat-db-v12-${UUID.randomUUID()}.db"
        val helper = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(databaseName)
                .callback(object : SupportSQLiteOpenHelper.Callback(12) {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        // Exact scan-session table shapes produced by schema v12.
                        db.execSQL(
                            "CREATE TABLE scan_sessions (session_id TEXT NOT NULL, scan_type TEXT NOT NULL, " +
                                "started_at INTEGER NOT NULL, completed_at INTEGER, status TEXT NOT NULL, " +
                                "PRIMARY KEY(session_id))"
                        )
                        db.execSQL("CREATE INDEX index_scan_sessions_started_at ON scan_sessions(started_at)")
                        db.execSQL("CREATE INDEX index_scan_sessions_status ON scan_sessions(status)")
                        db.execSQL(
                            "CREATE TABLE scan_session_state (session_id TEXT NOT NULL, total_items INTEGER NOT NULL, " +
                                "scanned_items INTEGER NOT NULL, current_item_path TEXT, scan_type TEXT NOT NULL, " +
                                "is_complete INTEGER NOT NULL, operation_type TEXT NOT NULL, source_uri TEXT, " +
                                "package_name TEXT, is_manual INTEGER NOT NULL, PRIMARY KEY(session_id))"
                        )
                        db.execSQL(
                            "CREATE TABLE scan_session_items (session_id TEXT NOT NULL, item_key TEXT NOT NULL, " +
                                "item_type TEXT NOT NULL, item_path TEXT NOT NULL, verdict TEXT NOT NULL, " +
                                "package_name TEXT, sha256_hash TEXT, md5_hash TEXT, reasons TEXT NOT NULL, " +
                                "risk_score REAL NOT NULL, detection_source TEXT NOT NULL, malware_name TEXT, " +
                                "threat_event_id TEXT, duration_ms INTEGER NOT NULL, source_uri TEXT, " +
                                "completed_at INTEGER NOT NULL, PRIMARY KEY(session_id, item_key))"
                        )
                        db.execSQL("CREATE INDEX index_scan_session_items_session_id ON scan_session_items(session_id)")
                        db.execSQL("CREATE INDEX index_scan_session_items_completed_at ON scan_session_items(completed_at)")
                    }

                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                        error("The fixture must be created as schema version 12, not upgraded automatically.")
                    }
                })
                .build()
        )

        try {
            val db = helper.writableDatabase
            db.execSQL(
                "INSERT INTO scan_sessions(session_id, scan_type, started_at, completed_at, status) " +
                    "VALUES('legacy-session', 'PERIODIC_DEEP_SCAN', 1000, 2000, 'COMPLETED')"
            )
            db.execSQL(
                "INSERT INTO scan_session_state(session_id, total_items, scanned_items, current_item_path, " +
                    "scan_type, is_complete, operation_type, source_uri, package_name, is_manual) " +
                    "VALUES('legacy-session', 10, 4, 'legacy-label', 'deep', 0, 'PERIODIC_DEEP_SCAN', NULL, NULL, 0)"
            )
            db.execSQL(
                "INSERT INTO scan_session_items(session_id, item_key, item_type, item_path, verdict, package_name, " +
                    "sha256_hash, md5_hash, reasons, risk_score, detection_source, malware_name, threat_event_id, " +
                    "duration_ms, source_uri, completed_at) " +
                    "VALUES('legacy-session', 'app:com.example.legacy', 'app', 'Legacy app', 'NO_MATCH', " +
                    "'com.example.legacy', 'sha256', NULL, '', 0, 'NONE', NULL, NULL, 51, NULL, 1500)"
            )

            ThreatDatabase.MIGRATION_12_13.migrate(db)

            db.query("SELECT scan_type, started_at, completed_at, status, elapsed_ms FROM scan_sessions").use { cursor ->
                assertEquals(1, cursor.count)
                assertEquals(true, cursor.moveToFirst())
                assertEquals("PERIODIC_DEEP_SCAN", cursor.getString(0))
                assertEquals(1000L, cursor.getLong(1))
                assertEquals(2000L, cursor.getLong(2))
                assertEquals("COMPLETED", cursor.getString(3))
                assertEquals(0L, cursor.getLong(4))
            }

            db.query(
                "SELECT total_items, scanned_items, operation_type, is_manual, enumerated_items, " +
                    "eligible_items, excluded_items FROM scan_session_state"
            ).use { cursor ->
                assertEquals(true, cursor.moveToFirst())
                assertEquals(10, cursor.getInt(0))
                assertEquals(4, cursor.getInt(1))
                assertEquals("PERIODIC_DEEP_SCAN", cursor.getString(2))
                assertEquals(0, cursor.getInt(3))
                assertEquals(0, cursor.getInt(4))
                assertEquals(0, cursor.getInt(5))
                assertEquals(0, cursor.getInt(6))
            }

            db.query(
                "SELECT item_key, verdict, package_name, duration_ms, completed_at, apk_size_bytes, " +
                    "scan_source, analysis_stages FROM scan_session_items"
            ).use { cursor ->
                assertEquals(true, cursor.moveToFirst())
                assertEquals("app:com.example.legacy", cursor.getString(0))
                assertEquals("NO_MATCH", cursor.getString(1))
                assertEquals("com.example.legacy", cursor.getString(2))
                assertEquals(51L, cursor.getLong(3))
                assertEquals(1500L, cursor.getLong(4))
                assertNull(cursor.getString(5))
                assertEquals("FRESH", cursor.getString(6))
                assertEquals("", cursor.getString(7))
            }
        } finally {
            helper.close()
            context.deleteDatabase(databaseName)
        }
    }
}
