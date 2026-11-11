package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.vibesync.antivirus.MainActivity

data class NotificationDeepLinkPayload(
    val notificationType: String,
    val fileUri: String?,
    val logId: String?
)

/** Shared, explicit notification-to-app navigation contract. */
object NotificationDeepLinkContract {
    const val EXTRA_NOTIFICATION_TYPE = "notification_type"
    const val EXTRA_FILE_URI = "file_uri"
    const val EXTRA_LOG_ID = "log_id"

    const val TYPE_INSTALL_PROGRESS = "INSTALL_PROGRESS"
    const val TYPE_INSTALL_TRUSTED = "INSTALL_TRUSTED"
    const val TYPE_DOWNLOAD_MALICIOUS = "DOWNLOAD_MALICIOUS"
    const val TYPE_DOWNLOAD_REVIEW = "DOWNLOAD_REVIEW"
    const val TYPE_DOWNLOAD_QUARANTINED = "DOWNLOAD_QUARANTINED"
    const val TYPE_MALWARE_APP = "MALWARE_APP"
    const val TYPE_SUSPICIOUS_APP = "SUSPICIOUS_APP"
    const val TYPE_SERVICE = "SERVICE"

    fun intent(context: Context, notificationType: String, fileUri: String?, logId: String?): Intent {
        val identity = logId?.takeIf(String::isNotBlank) ?: fileUri ?: "default"
        return Intent(context, MainActivity::class.java).apply {
            action = "com.vibesync.antivirus.action.OPEN_NOTIFICATION"
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(EXTRA_NOTIFICATION_TYPE, notificationType.take(64))
            putExtra(EXTRA_FILE_URI, fileUri?.take(2048))
            putExtra(EXTRA_LOG_ID, logId?.take(160))
            data = Uri.fromParts("safe-mobile-notification", "$notificationType:$identity", null)
        }
    }

    fun fromIntent(intent: Intent?): NotificationDeepLinkPayload? {
        val type = intent?.getStringExtra(EXTRA_NOTIFICATION_TYPE)
            ?.takeIf { it in TYPES } ?: return null
        val fileUri = intent.getStringExtra(EXTRA_FILE_URI)?.takeIf { it.length <= 2048 }
        val logId = intent.getStringExtra(EXTRA_LOG_ID)?.takeIf { it.isNotBlank() && it.length <= 160 }
        return NotificationDeepLinkPayload(type, fileUri, logId)
    }

    private val TYPES = setOf(
        TYPE_INSTALL_PROGRESS, TYPE_INSTALL_TRUSTED, TYPE_DOWNLOAD_MALICIOUS,
        TYPE_DOWNLOAD_REVIEW, TYPE_DOWNLOAD_QUARANTINED, TYPE_MALWARE_APP,
        TYPE_SUSPICIOUS_APP, TYPE_SERVICE
    )
}
