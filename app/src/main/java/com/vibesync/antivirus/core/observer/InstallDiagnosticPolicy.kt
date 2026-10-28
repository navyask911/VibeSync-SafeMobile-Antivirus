package com.vibesync.antivirus.core.observer

/** A diagnostic alarm is never a malware verdict and never changes the threat database. */
internal object InstallDiagnosticPolicy {
    const val FIXTURE_PACKAGE = "com.safemobile.sirentest"

    fun shouldTest(packageName: String, debugBuild: Boolean): Boolean =
        packageName == FIXTURE_PACKAGE || (debugBuild &&
            packageName.replace("_", "").replace("-", "").contains("sirentest", ignoreCase = true))
}

/** One alarm per event in this process; new installs remain audible. Bounded, timer-free state. */
internal class InstallAlarmGate(private val capacity: Int = 256) {
    init { require(capacity > 0) }
    private val events = LinkedHashSet<String>()
    @Synchronized fun claim(eventId: String): Boolean {
        if (!events.add(eventId)) return false
        while (events.size > capacity) events.remove(events.first())
        return true
    }
}
