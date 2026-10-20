import org.jetbrains.kotlin.gradle.dsl.JvmTarget
plugins {
 id("com.android.application")
 id("org.jetbrains.kotlin.android")
 id("org.jetbrains.kotlin.kapt")
 id("org.jetbrains.kotlin.plugin.compose")
}
fun cfg(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
android {
 namespace = "com.vibesync.antivirus"
 compileSdk = 35
 defaultConfig {
  applicationId = "com.vibesync.antivirus"
  minSdk = 26
  targetSdk = 35
  versionCode = 2026102001
  versionName = "1.0.0"
  testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  manifestPlaceholders["admobAppId"] = "ca-app-pub-4783826505860771~8485727119"
  buildConfigField("String", "BANNER_AD_UNIT_ID", cfg("ca-app-pub-4783826505860771/4710308648"))
  buildConfigField("String", "INTERSTITIAL_AD_UNIT_ID", cfg("ca-app-pub-4783826505860771/9523651625"))
  buildConfigField("String", "COFFEE_SUPPORT_URL", cfg("https://github.com/sponsors/navyask911"))
 }
 buildTypes {
  debug {
   applicationIdSuffix = ".debug"
   versionNameSuffix = "-debug"
   manifestPlaceholders["admobAppId"] = "ca-app-pub-3940256099942544~3347511713"
   buildConfigField("String", "BANNER_AD_UNIT_ID", cfg("ca-app-pub-3940256099942544/9214589741"))
   buildConfigField("String", "INTERSTITIAL_AD_UNIT_ID", cfg("ca-app-pub-3940256099942544/1033173712"))
  }
  release {
   isMinifyEnabled = true
   isShrinkResources = true
   ndk { debugSymbolLevel = "FULL" }
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
