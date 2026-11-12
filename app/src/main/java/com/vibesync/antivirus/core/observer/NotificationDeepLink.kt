package com.vibesync.antivirus.core.observer

import android.content.Intent

/** Minimal, explicit payload routed from a notification into the normal app navigation. */
data class NotificationDeepLink(
    val notificationType: String,
    val fileUri: String? = null,
    val logId: String? = null,
    val fileName: String? = null,
    val filePath: String? = null,
    val reason: String? = null,
    val packageName: String? = null
) {
    companion object {
        const val EXTRA_NOTIFICATION_TYPE = "notification_type"
        const val EXTRA_FILE_URI = "file_uri"
        const val EXTRA_LOG_ID = "log_id"
        const val EXTRA_FILE_NAME = "file_name"
        const val EXTRA_FILE_PATH = "file_path"
        const val EXTRA_REASON = "reason"
        const val EXTRA_PACKAGE_NAME = "package_name"

        fun fromIntent(intent: Intent?): NotificationDeepLink? {
            if (intent == null) return null
            val type = intent.getStringExtra(EXTRA_NOTIFICATION_TYPE)
                ?.trim()?.takeIf(String::isNotEmpty) ?: return null
            val logId = intent.getStringExtra(EXTRA_LOG_ID)
                ?: intent.getLongExtra(EXTRA_LOG_ID, -1L).takeIf { it >= 0L }?.toString()
            return NotificationDeepLink(
                notificationType = type.take(80),
                fileUri = intent.getStringExtra(EXTRA_FILE_URI)?.take(4096),
                logId = logId?.take(160),
                fileName = intent.getStringExtra(EXTRA_FILE_NAME)?.take(240),
                filePath = intent.getStringExtra(EXTRA_FILE_PATH)?.take(4096),
                reason = intent.getStringExtra(EXTRA_REASON)?.take(1000),
                packageName = intent.getStringExtra(EXTRA_PACKAGE_NAME)?.take(200)
            )
        }
    }
}
