package com.vibesync.antivirus.core.posture

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.locale.LocalePreferences
import java.security.MessageDigest

/** Change alerts are not malware verdicts: no siren, TTS accusation, or full-screen interruption. */
object PostureChangeNotifier {
    const val EXTRA_OPEN_POSTURE = "com.vibesync.antivirus.OPEN_DEVICE_POSTURE"
    private const val CHANNEL = "safe_mobile_posture_changes_v1"

    fun notify(context: Context, change: PostureChange, finding: PostureFinding): Boolean {
        if (!context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
                .getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)) return false
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(context,
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return false
        return runCatching {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return@runCatching false
            val localized = LocalePreferences.wrap(context)
            manager.createNotificationChannel(NotificationChannel(CHANNEL,
                localized.getString(R.string.posture_change_channel), NotificationManager.IMPORTANCE_HIGH))
            if (!NotificationManagerCompat.from(context).areNotificationsEnabled() ||
                manager.getNotificationChannel(CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE) return@runCatching false
            val key = change.capability.access.name + ":" + change.capability.packageName + ":" + change.observedAt
            val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
            val id = ((digest[0].toInt() and 127) shl 24) or ((digest[1].toInt() and 255) shl 16) or
                ((digest[2].toInt() and 255) shl 8) or (digest[3].toInt() and 255)
            val open = Intent(context, MainActivity::class.java).putExtra(EXTRA_OPEN_POSTURE, true)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .setData(Uri.fromParts("safemobile-posture", key, null))
            val pending = PendingIntent.getActivity(context, id, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val message = localized.getString(R.string.posture_change_body, finding.appName.take(100),
                localized.getString(PostureText.title(finding.access)), localized.getString(PostureText.explanation(finding)))
            NotificationManagerCompat.from(context).notify("posture", id, NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher).setContentTitle(localized.getString(R.string.posture_change_title))
                .setContentText(message).setStyle(NotificationCompat.BigTextStyle().bigText(message))
                .setContentIntent(pending).addAction(0, localized.getString(R.string.posture_review), pending)
                .setCategory(NotificationCompat.CATEGORY_STATUS).setPriority(NotificationCompat.PRIORITY_HIGH)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setAutoCancel(true).setOnlyAlertOnce(true).build())
            true
        }.getOrDefault(false)
    }
}
