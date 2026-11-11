package com.vibesync.antivirus.presentation

import android.content.Context
import android.os.Build
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.compose.runtime.Immutable
import com.vibesync.antivirus.R
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.protectionAdvisorDataStore by preferencesDataStore(name = "safemobile_protection_advisor")

enum class AdvisorIssueGroup { CRITICAL, MINOR, SNOOZED, COMPLETED }

@Immutable
data class AdvisorIssueItem(
    val id: String,
    val titleResource: Int,
    val detailResource: Int,
    val points: Int,
    val group: AdvisorIssueGroup,
    val destination: String,
    val canSnooze: Boolean = true
)

@Immutable
data class ProtectionAdvisorState(
    val score: Int,
    val pendingCount: Int,
    val issues: List<AdvisorIssueItem>
) {
    val critical: List<AdvisorIssueItem> get() = issues.filter { it.group == AdvisorIssueGroup.CRITICAL }
    val minor: List<AdvisorIssueItem> get() = issues.filter { it.group == AdvisorIssueGroup.MINOR }
    val snoozed: List<AdvisorIssueItem> get() = issues.filter { it.group == AdvisorIssueGroup.SNOOZED }
    val completed: List<AdvisorIssueItem> get() = issues.filter { it.group == AdvisorIssueGroup.COMPLETED }
}

/** Presentation-only action rubric. It consumes observations from existing repositories and OS APIs. */
data class ProtectionAdvisorInputs(
    val totalScans: Int,
    val threatsDetected: Int,
    val folderSentinelConfigured: Boolean,
    val highRiskPostureCount: Int?,
    val notificationsEnabled: Boolean,
    val batteryUnrestricted: Boolean,
    val fullScreenIntentEnabled: Boolean,
    val databaseUpdatedAt: Long?,
    val installSentinelEnabled: Boolean,
    val playProtectEnabled: Boolean?,
    val usbDebuggingEnabled: Boolean?,
    val voiceAlertsEnabled: Boolean,
    val apiLevel: Int = Build.VERSION.SDK_INT,
    val nowMillis: Long = System.currentTimeMillis()
)

object ProtectionAdvisorEngine {
    private const val SCORE_MAX = 100
    private const val WEEK_MS = 7L * 24 * 60 * 60 * 1000

    fun evaluate(inputs: ProtectionAdvisorInputs, snoozedIds: Set<String>): ProtectionAdvisorState {
        val scanned = inputs.totalScans > 0
        val databaseFresh = inputs.databaseUpdatedAt?.let {
            it > 0L && it <= inputs.nowMillis && inputs.nowMillis - it < WEEK_MS
        } == true
        val raw = listOf(
            issue("initial_scan_run", R.string.security_scan_now, R.string.scan_explanation, 15, scanned, "scan"),
            issue("active_threats", R.string.threat_found, R.string.scan_clean_warning, 25,
                scanned && inputs.threatsDetected == 0, "scan", canSnooze = false,
                activeThreat = scanned && inputs.threatsDetected > 0),
            issue("folder_sentinel", R.string.nav_sentinel, R.string.monitor_explanation, 10,
                inputs.folderSentinelConfigured, "sentinel"),
            issue("high_risk_posture", R.string.posture_title, R.string.posture_risk_note, 12,
                inputs.highRiskPostureCount == 0, "posture",
                activeThreat = (inputs.highRiskPostureCount ?: 0) > 0),
            issue("notifications_on", R.string.security_alerts_title, R.string.incident_alerts_explanation,
                8, inputs.notificationsEnabled, "settings"),
            issue("battery_unrestricted", R.string.battery_review_title, R.string.battery_review_body,
                6, inputs.batteryUnrestricted, "settings"),
            issue("fullscreen_alert", R.string.incident_full_screen_settings,
                R.string.incident_full_screen_explanation, 5,
                inputs.apiLevel < 34 || inputs.fullScreenIntentEnabled, "settings"),
            issue("db_freshness", R.string.ui_score_database, R.string.ui_stale_10, 5,
                databaseFresh, "capabilities"),
            issue("install_sentinel", R.string.setup_sentinel_title, R.string.setup_sentinel_body,
                15, inputs.installSentinelEnabled, "sentinel"),
            issue("play_protect_adb", R.string.guardian_developer_settings,
                R.string.guardian_settings_limit, 4,
                inputs.playProtectEnabled == true && inputs.usbDebuggingEnabled == false, "guardian"),
            issue("voice_alert_tts", R.string.voice_alerts_title, R.string.voice_alerts_description,
                4, inputs.voiceAlertsEnabled, "settings")
        )
        val mapped = raw.map { item ->
            when {
                item.completed -> item.copy(group = AdvisorIssueGroup.COMPLETED)
                item.activeThreat -> item.copy(group = AdvisorIssueGroup.CRITICAL)
                item.id in snoozedIds && item.canSnooze -> item.copy(group = AdvisorIssueGroup.SNOOZED)
                item.points >= 12 -> item.copy(group = AdvisorIssueGroup.CRITICAL)
                else -> item.copy(group = AdvisorIssueGroup.MINOR)
            }
        }
        val pendingDeductions = mapped.filter {
            it.group == AdvisorIssueGroup.CRITICAL || it.group == AdvisorIssueGroup.MINOR
        }.sumOf { it.points }
        // Scores are direct deductions from 100. Snoozed/completed actions do not
        // lower the score; the aggregate is clamped because pending penalties can
        // exceed the available range when several high-risk actions coexist.
        val score = (SCORE_MAX - pendingDeductions).coerceIn(0, SCORE_MAX)
        val pending = mapped.count { it.group == AdvisorIssueGroup.CRITICAL || it.group == AdvisorIssueGroup.MINOR }
        return ProtectionAdvisorState(score, pending, mapped)
    }

    private data class RawIssue(
        val id: String,
        val title: Int,
        val detail: Int,
        val points: Int,
        val completed: Boolean,
        val destination: String,
        val canSnooze: Boolean,
        val activeThreat: Boolean
    )

    private fun issue(
        id: String, title: Int, detail: Int, points: Int, completed: Boolean,
        destination: String, canSnooze: Boolean = true, activeThreat: Boolean = false
    ) = RawIssue(id, title, detail, points, completed, destination, canSnooze, activeThreat)

    private fun RawIssue.copy(group: AdvisorIssueGroup) = AdvisorIssueItem(
        id = id, titleResource = title, detailResource = detail, points = points,
        group = group, destination = destination, canSnooze = canSnooze
    )
}

class ProtectionAdvisorStore(context: Context) {
    private val appContext = context.applicationContext
    private val key = stringSetPreferencesKey("snoozed_issue_ids")
    val snoozedIssueIds: Flow<Set<String>> =
        appContext.protectionAdvisorDataStore.data.map { it[key].orEmpty() }

    suspend fun setSnoozed(issueId: String, snoozed: Boolean) {
        appContext.protectionAdvisorDataStore.edit { prefs ->
            val current = prefs[key].orEmpty().toMutableSet()
            if (snoozed) current += issueId else current -= issueId
            prefs[key] = current
        }
    }
}
