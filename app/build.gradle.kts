import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Base64
plugins {
 id("com.android.application")
 id("org.jetbrains.kotlin.android")
 id("org.jetbrains.kotlin.kapt")
 id("org.jetbrains.kotlin.plugin.compose")
}
fun cfg(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val feedManifestPublicKey = providers.environmentVariable("SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64").orNull?.trim().orEmpty()
val hashDatabasePublicKey = providers.environmentVariable("SAFE_MOBILE_HASHDB_ED25519_PUBLIC_KEY_B64").orNull?.trim().orEmpty()
val releaseStoreBase64 = providers.environmentVariable("KEYSTORE_BASE64").orNull
val releaseStorePassword = providers.environmentVariable("KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("KEY_PASSWORD").orNull
val signingValues = listOf(releaseStoreBase64, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
val releaseSigningEnabled = signingValues.all { !it.isNullOrBlank() }
if (signingValues.any { !it.isNullOrBlank() } && !releaseSigningEnabled) {
    throw GradleException("Release signing is partially configured. Set all four KEYSTORE_BASE64, KEYSTORE_PASSWORD, KEY_ALIAS and KEY_PASSWORD variables, or leave all empty.")
}

android {
 namespace = "com.vibesync.antivirus"
 compileSdk = 36
 flavorDimensions += "network"
 productFlavors {
  create("offline") {
   dimension = "network"
   buildConfigField("Boolean", "OPTIONAL_FEED_ENABLED", "false")
  }
  create("feed") {
   dimension = "network"
   buildConfigField("Boolean", "OPTIONAL_FEED_ENABLED", "true")
  }
 }
 defaultConfig {
  applicationId = "com.vibesync.antivirus"
  minSdk = 26
  targetSdk = 36
  versionCode = 20261111
  versionName = "1.0.18"
  testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  buildConfigField("String", "FEED_MANIFEST_PUBLIC_KEY_B64", cfg(feedManifestPublicKey))
  buildConfigField("Boolean", "FEED_MANIFEST_KEY_CONFIGURED", (!feedManifestPublicKey.isBlank()).toString())
  buildConfigField("String", "HASHDB_PUBLIC_KEY_B64", cfg(hashDatabasePublicKey))
  buildConfigField("Boolean", "HASHDB_PUBLIC_KEY_CONFIGURED", (!hashDatabasePublicKey.isBlank()).toString())
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

// docs/BENCHMARK_REPORT.md is canonical: the hidden card reads its build-time asset copy.
// Generated assets are not committed and never contain APK samples.
val benchmarkAssetDirectory = layout.buildDirectory.dir("generated/benchmark-report/assets")
val stageBenchmarkReport = tasks.register<Copy>("stageBenchmarkReport") {
    from(rootProject.file("docs/BENCHMARK_REPORT.md"))
    into(benchmarkAssetDirectory)
    rename { "benchmark-report.md" }
}
// Register the producing TaskProvider, not just its build/ path. This propagates
// Gradle's builtBy dependency to lint model writers and all variant asset consumers.
android.sourceSets.getByName("main").assets.srcDir(stageBenchmarkReport)
// AGP's vital lint tasks inspect assets separately from merge<Variant>Assets.
// Keep an explicit dependency as a belt-and-braces guard across AGP upgrades.
tasks.matching {
    (it.name.startsWith("merge") && it.name.endsWith("Assets")) ||
        // Lint creates both generate<Variant>LintVitalReportModel and
        // generate<Variant>LintReportModel; matching only LintModel misses the latter.
        (it.name.startsWith("generate") && it.name.contains("Lint") && it.name.endsWith("Model"))
}.configureEach {
    dependsOn(stageBenchmarkReport)
}

kapt { correctErrorTypes = true }
dependencies {
 implementation("androidx.core:core-ktx:1.16.0")
 implementation("androidx.datastore:datastore-preferences:1.3.0")
 implementation("androidx.documentfile:documentfile:1.0.1")
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
 // Google Android SDK License: Play Billing is only for explicit checkout, never scanning.
 implementation("com.android.billingclient:billing-ktx:8.3.0")
 // Apache-2.0: KeyStore-backed encrypted local device-bound entitlement.
 implementation("androidx.security:security-crypto:1.1.0")
 // TensorFlow Lite 2.17.0 is local inference only; no model training or network calls.
 implementation("org.tensorflow:tensorflow-lite:2.17.0")
 // Apache-2.0 OkHttp is confined to the opt-in weekly model download worker.
 implementation("com.squareup.okhttp3:okhttp:4.12.0")
 // BSD-3-Clause: structured read-only DEX parsing of 215 research features.
 implementation("org.smali:dexlib2:2.5.2")
 implementation("com.google.guava:guava:33.4.8-android")
 implementation("org.bouncycastle:bcprov-jdk18on:1.86")
 // The instrumentation APK is separate from the app APK and must carry its own Kotlin runtime.
 androidTestImplementation(kotlin("stdlib"))
 androidTestImplementation("androidx.test:runner:1.6.2")
 androidTestImplementation("androidx.test.ext:junit:1.2.1")
 androidTestImplementation("androidx.test:core:1.6.1")
 androidTestImplementation("androidx.room:room-testing:2.7.2")
 testImplementation("org.json:json:20240303")
 testImplementation("junit:junit:4.13.2")
 testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

