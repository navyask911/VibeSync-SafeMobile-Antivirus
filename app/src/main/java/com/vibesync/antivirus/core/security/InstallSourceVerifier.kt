package com.vibesync.antivirus.core.security
import android.content.Context
import android.os.Build

enum class InstallSourceCategory { PLAY_STORE, EXTERNAL, UNKNOWN }
data class InstallSourceAssessment(
 val packageName: String,
 val category: InstallSourceCategory,
 val initiatingPackageName: String?,
 val installingPackageName: String?,
 val originatingPackageName: String?,
 val sourceLabel: String,
 val isBrowserOrMessenger: Boolean
) { val needsReview: Boolean get() = category != InstallSourceCategory.PLAY_STORE }

/** Install metadata is best-effort; missing metadata is UNKNOWN, not proof of sideloading. */
class InstallSourceVerifier(context: Context) {
 private val pm = context.applicationContext.packageManager
 fun inspect(packageName: String): InstallSourceAssessment {
  var initiating: String? = null
  var installing: String? = null
  var originating: String? = null
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) runCatching { pm.getInstallSourceInfo(packageName) }.onSuccess {
   initiating = it.initiatingPackageName; installing = it.installingPackageName; originating = it.originatingPackageName
  }
  if (installing.isNullOrBlank()) {
   @Suppress("DEPRECATION")
   installing = runCatching { pm.getInstallerPackageName(packageName) }.getOrNull()
  }
  if (initiating.isNullOrBlank()) initiating = installing
  val observed = listOfNotNull(initiating, installing, originating).map { it.trim() }.filter { it.isNotEmpty() }.distinct()
  val play = initiating == PLAY_STORE || installing == PLAY_STORE
  val known = observed.firstOrNull { it in BROWSERS || it in MESSENGERS }
  val category = when { play -> InstallSourceCategory.PLAY_STORE; observed.isNotEmpty() -> InstallSourceCategory.EXTERNAL; else -> InstallSourceCategory.UNKNOWN }
  return InstallSourceAssessment(packageName, category, initiating, installing, originating,
   when { play -> "Google Play Store"; known != null -> known; category == InstallSourceCategory.EXTERNAL -> observed.first(); else -> "Unknown / not reported by Android" },
   known != null)
 }
 companion object {
  const val PLAY_STORE = "com.android.vending"
  private val BROWSERS = setOf("com.android.chrome","org.mozilla.firefox","com.microsoft.emmx","com.brave.browser","com.opera.browser","com.sec.android.app.sbrowser","com.android.browser","com.duckduckgo.mobile.android")
  private val MESSENGERS = setOf("com.whatsapp","org.telegram.messenger","com.facebook.orca","com.viber.voip","com.discord","com.skype.raider","org.thoughtcrime.securesms")
 }
}
