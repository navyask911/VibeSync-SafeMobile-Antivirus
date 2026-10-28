package com.vibesync.antivirus.core.observer

/** A diagnostic alarm is never a malware verdict and never changes the threat database. */
internal object InstallDiagnosticPolicy {
    const val FIXTURE_PACKAGE = "com.safemobile.sirentest"

    fun shouldTest(packageName: String, debugBuild: Boolean): Boolean =
        packageName == FIXTURE_PACKAGE || (debugBuild &&
            packageName.replace("_", "").replace("-", "").contains("sirentest", ignoreCase = true))
}
