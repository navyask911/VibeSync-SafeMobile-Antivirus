package com.vibesync.antivirus.ads
import android.app.Activity
import com.google.android.ump.ConsentInformation
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform

object ConsentManager {
 fun requestConsent(activity: Activity, onFinished: (Boolean) -> Unit) {
  val info=UserMessagingPlatform.getConsentInformation(activity)
  info.requestConsentInfoUpdate(activity,ConsentRequestParameters.Builder().build(),{
   UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) { onFinished(info.canRequestAds()) }
  },{
   onFinished(info.canRequestAds())
  })
 }
 fun showPrivacyOptions(activity: Activity, onFinished: (Boolean) -> Unit = {}) {
  val info=UserMessagingPlatform.getConsentInformation(activity)
  UserMessagingPlatform.showPrivacyOptionsForm(activity) { onFinished(info.canRequestAds()) }
 }
 fun privacyOptionsRequired(activity: Activity): Boolean =
  UserMessagingPlatform.getConsentInformation(activity).privacyOptionsRequirementStatus ==
   ConsentInformation.PrivacyOptionsRequirementStatus.REQUIRED
}
