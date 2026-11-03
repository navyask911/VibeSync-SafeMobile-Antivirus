plugins {
    id("org.cyclonedx.bom") version "3.5.1"
 id("app.cash.paparazzi") version "2.0.0-alpha02" apply false
 id("com.android.application") version "8.13.2" apply false
 id("org.jetbrains.kotlin.android") version "2.2.21" apply false
 id("org.jetbrains.kotlin.kapt") version "2.2.21" apply false
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
