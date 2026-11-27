// AGP 9.0 bundles Kotlin 2.2.10. Keep the app on the project's tested Kotlin
// compiler level while using AGP's built-in Android Kotlin integration.
buildscript {
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.21")
    }
}

plugins {
    id("org.cyclonedx.bom") version "3.6.1"
    id("app.cash.paparazzi") version "2.0.0-alpha05.1" apply false
    id("com.android.application") version "9.0.1" apply false
    id("com.android.legacy-kapt") version "9.0.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.21" apply false
}

// Explicit Maven coordinates for CycloneDX and downstream artifact metadata.
// Keep synchronized with app/defaultConfig.versionName when cutting a release.
allprojects {
    group = "com.vibesync.antivirus"
    version = "1.5.1"
}


tasks.register("recordPaparazziDebug") {
    group = "verification"
    description = "Record Paparazzi goldens for the offline debug variant."
    dependsOn(":app:recordPaparazziOfflineDebug")
}

tasks.register("verifyPaparazziDebug") {
    group = "verification"
    description = "Verify Paparazzi goldens for the offline debug variant."
    dependsOn(":app:verifyPaparazziOfflineDebug")
}
