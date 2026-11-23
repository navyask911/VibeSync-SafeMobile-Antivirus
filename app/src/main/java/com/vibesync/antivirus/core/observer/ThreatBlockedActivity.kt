package com.vibesync.antivirus.core.observer

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import java.io.File

class ThreatBlockedActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(com.vibesync.antivirus.core.locale.LocalePreferences.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )

        val kind = intent.getStringExtra(EXTRA_EVENT_KIND).orEmpty()
        val confirmed = intent.getBooleanExtra(EXTRA_CONFIRMED_MALICIOUS, false)
        val title = when {
            confirmed -> R.string.blocked_activity_title_confirmed
            kind == "DOWNLOAD_QUARANTINED" -> R.string.blocked_activity_title_quarantine
            kind == "DOWNLOAD_REVIEW" -> R.string.blocked_activity_title_review
            else -> R.string.blocked_activity_title_interrupted
        }
        val name = intent.getStringExtra(EXTRA_FILENAME)?.let { File(it).name }?.take(120)
        val installer = intent.getStringExtra(EXTRA_INSTALLER)
            ?.takeIf { it.matches(Regex("^[A-Za-z0-9_.]+$")) }
            ?.take(160)
        val reason = getString(
            if (intent.getStringExtra(EXTRA_REASON) == "local_sha256_match") {
                R.string.blocked_reason_hash
            } else {
                R.string.blocked_reason_action
            }
        )

        val edgePadding = dp(24)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(edgePadding, edgePadding, edgePadding, edgePadding)
            setBackgroundColor(Color.rgb(18, 22, 30))
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        root.addView(
            TextView(this).apply {
                text = getString(title)
                textSize = 24f
                setTextColor(Color.WHITE)
                setPadding(0, 0, 0, dp(16))
            }
        )
        root.addView(
            TextView(this).apply {
                text = getString(R.string.blocked_activity_body)
                textSize = 16f
                setTextColor(Color.LTGRAY)
                setPadding(0, 0, 0, dp(18))
            }
        )
        if (!name.isNullOrBlank() && (name.endsWith(".apk", true) || name.endsWith(".exe", true))) {
            root.addView(info(getString(R.string.blocked_activity_filename, name)))
        }
        if (!installer.isNullOrBlank()) {
            root.addView(info(getString(R.string.blocked_activity_installer, installer)))
        }
        root.addView(info(getString(R.string.blocked_activity_reason, reason)))
        root.addView(
            Button(this).apply {
                text = getString(R.string.blocked_activity_open_app)
                setOnClickListener {
                    startActivity(
                        Intent(this@ThreatBlockedActivity, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    )
                    finish()
                }
            }
        )
        root.addView(
            Button(this).apply {
                text = getString(R.string.blocked_activity_done)
                setOnClickListener { finish() }
            }
        )

        // Keep content inside system bars and display cutouts while the root background
        // continues drawing edge-to-edge behind the system UI.
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, windowInsets ->
            val safeInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            view.setPadding(
                edgePadding + safeInsets.left,
                edgePadding + safeInsets.top,
                edgePadding + safeInsets.right,
                edgePadding + safeInsets.bottom
            )
            windowInsets
        }
        setContentView(root)
        ViewCompat.requestApplyInsets(root)
    }

    private fun info(value: String) = TextView(this).apply {
        text = value
        textSize = 14f
        setTextColor(Color.LTGRAY)
        setPadding(0, dp(5), 0, dp(5))
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_EVENT_KIND = "safe_mobile_event_kind"
        const val EXTRA_FILENAME = "safe_mobile_filename"
        const val EXTRA_INSTALLER = "safe_mobile_installer_package"
        const val EXTRA_REASON = "safe_mobile_reason"
        const val EXTRA_EVENT_ID = "safe_mobile_event_id"
        const val EXTRA_CONFIRMED_MALICIOUS = "safe_mobile_confirmed_malicious"
    }
}
