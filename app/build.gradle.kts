import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Base64
plugins {
 id("com.android.application")
 id("org.jetbrains.kotlin.android")
 id("org.jetbrains.kotlin.kapt")
 id("org.jetbrains.kotlin.plugin.compose")
}
fun cfg(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val releaseStoreBase64 = providers.environmentVariable("KEYSTORE_BASE64").orNull
val releaseStorePassword = providers.environmentVariable("KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("KEY_PASSWORD").orNull
val releaseAdMobAppId = providers.environmentVariable("ADMOB_APP_ID").orNull
val releaseBannerUnitId = providers.environmentVariable("ADMOB_BANNER_UNIT_ID").orNull
val releaseInterstitialUnitId = providers.environmentVariable("ADMOB_INTERSTITIAL_UNIT_ID").orNull
val releaseAdValues = listOf(releaseAdMobAppId, releaseBannerUnitId, releaseInterstitialUnitId)
val releaseAdsConfigured = releaseAdValues.all { !it.isNullOrBlank() }
if (releaseAdValues.any { !it.isNullOrBlank() } && !releaseAdsConfigured) {
    throw GradleException("AdMob release configuration is partial. Set ADMOB_APP_ID, ADMOB_BANNER_UNIT_ID and ADMOB_INTERSTITIAL_UNIT_ID, or leave all empty.")
}
val testAdMobAppId = "ca-app-pub-3940256099942544~3347511713"
val testBannerUnitId = "ca-app-pub-3940256099942544/9214589741"
val testInterstitialUnitId = "ca-app-pub-3940256099942544/1033173712"
val signingValues = listOf(releaseStoreBase64, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
val releaseSigningEnabled = signingValues.all { !it.isNullOrBlank() }
if (signingValues.any { !it.isNullOrBlank() } && !releaseSigningEnabled) {
    throw GradleException("Release signing is partially configured. Set all four KEYSTORE_BASE64, KEYSTORE_PASSWORD, KEY_ALIAS and KEY_PASSWORD variables, or leave all empty.")
}

android {
 namespace = "com.vibesync.antivirus"
 compileSdk = 35
 defaultConfig {
  applicationId = "com.vibesync.antivirus"
  minSdk = 26
  targetSdk = 35
  versionCode = 20261020
  versionName = "1.0.0"
  testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  manifestPlaceholders["admobAppId"] = releaseAdMobAppId?.takeIf { it.isNotBlank() } ?: testAdMobAppId
  buildConfigField("String", "BANNER_AD_UNIT_ID", cfg(releaseBannerUnitId?.takeIf { it.isNotBlank() } ?: ""))
  buildConfigField("String", "INTERSTITIAL_AD_UNIT_ID", cfg(releaseInterstitialUnitId?.takeIf { it.isNotBlank() } ?: ""))
  buildConfigField("Boolean", "ADS_CONFIGURED", releaseAdsConfigured.toString())
  buildConfigField("String", "COFFEE_SUPPORT_URL", cfg("https://github.com/sponsors/navyask911"))
 }
 signingConfigs {
  if (releaseSigningEnabled) {
   create("release") {
    val keystoreFile = layout.buildDirectory.file("signing/safemobile-release.jks").get().asFile
    if (!keystoreFile.isFile) {
     keystoreFile.parentFile.mkdirs()
     keystoreFile.writeBytes(Base64.getDecoder().decode(releaseStoreBase64))
    }
    storeFile = keystoreFile
    storePassword = releaseStorePassword
    keyAlias = releaseKeyAlias
    keyPassword = releaseKeyPassword
   }
  }
 }
 buildTypes {
  debug {
   applicationIdSuffix = ".debug"
   versionNameSuffix = "-debug"
   manifestPlaceholders["admobAppId"] = testAdMobAppId
   buildConfigField("String", "BANNER_AD_UNIT_ID", cfg(testBannerUnitId))
   buildConfigField("String", "INTERSTITIAL_AD_UNIT_ID", cfg(testInterstitialUnitId))
   buildConfigField("Boolean", "ADS_CONFIGURED", "true")
  }
  release {
   isMinifyEnabled = true
   isShrinkResources = true
   ndk { debugSymbolLevel = "FULL" }
   if (releaseSigningEnabled) signingConfig = signingConfigs.getByName("release")
   proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
  }
 }
 buildFeatures { compose = true; buildConfig = true }
 compileOptions {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
 }
 kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
 packaging { resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1") }
}
kapt { correctErrorTypes = true }
dependencies {
 implementation("androidx.core:core-ktx:1.16.0")
 implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
 implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.1")
 implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.1")
 implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.1")
 implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.1")
 implementation(platform("androidx.compose:compose-bom:2025.05.01"))
 implementation("androidx.compose.ui:ui")
 implementation("androidx.compose.ui:ui-tooling-preview")
 implementation("androidx.compose.foundation:foundation")
 implementation("androidx.compose.material3:material3")
 implementation("androidx.compose.material:material-icons-extended")
 debugImplementation("androidx.compose.ui:ui-tooling")
 implementation("androidx.room:room-runtime:2.7.2")
 implementation("androidx.room:room-ktx:2.7.2")
 kapt("androidx.room:room-compiler:2.7.2")
 implementation("androidx.work:work-runtime-ktx:2.10.2")
 implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
 implementation("com.google.crypto.tink:tink-android:1.16.0")
 implementation("com.google.android.gms:play-services-ads:25.5.0")
 implementation("com.google.android.ump:user-messaging-platform:4.0.0")
 implementation("com.google.android.play:app-update-ktx:2.1.0")
 testImplementation("junit:junit:4.13.2")
 testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}
