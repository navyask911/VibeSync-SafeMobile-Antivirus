plugins {
    id("org.cyclonedx.bom") version "3.5.1"
 id("com.android.application") version "8.13.2" apply false
 id("org.jetbrains.kotlin.android") version "2.2.21" apply false
 id("org.jetbrains.kotlin.kapt") version "2.2.21" apply false
 id("org.jetbrains.kotlin.plugin.compose") version "2.2.21" apply false
}

// Explicit Maven coordinates for CycloneDX and downstream artifact metadata.
// Keep synchronized with app/defaultConfig.versionName when cutting a release.
allprojects {
    group = "com.vibesync.antivirus"
    version = "1.0.18"
}
