package com.vibesync.antivirus.core.posture

import com.vibesync.antivirus.core.security.TrustedPackageWhitelist

enum class PostureAccess { ACCESSIBILITY, DEVICE_ADMIN, NOTIFICATION_LISTENER, OVERLAY }
enum class PostureGrantState { ENABLED, NOT_GRANTED, UNKNOWN }

/** A capability observation, never a malware verdict or a claim that content was accessed. */
data class PostureFinding(
    val access: PostureAccess,
    val packageName: String,
    val appName: String,
    val componentName: String? = null,
    val systemApp: Boolean? = null,
    val state: PostureGrantState = PostureGrantState.ENABLED,
    val canReadScreen: Boolean? = null,
    val stale: Boolean = false
) {
    val highRisk: Boolean get() = state == PostureGrantState.ENABLED &&
        systemApp == false && !TrustedPackageWhitelist.hasProtectedNamespace(packageName)
    val nonSystemHighRisk: Boolean get() = highRisk
}

data class DevicePostureReport(
    val findings: List<PostureFinding>,
    val unavailable: Set<PostureAccess>,
    val checkedAt: Long
) {
    val highRiskAppCount: Int get() = findings.filter { it.nonSystemHighRisk }.map { it.packageName }.distinct().size
    fun grants(access: PostureAccess): Set<PostureCapability> = findings.asSequence()
        .filter { it.access == access && it.state == PostureGrantState.ENABLED && it.systemApp == false &&\n            !TrustedPackageWhitelist.hasProtectedNamespace(it.packageName) }
        .map { PostureCapability(it.access, it.packageName) }.toSet()

    /** Do not erase a previously observed risk just because a later Android read is unavailable. */
    fun retainingUnavailable(previous: DevicePostureReport?): DevicePostureReport {
        if (previous == null) return this
        fun key(finding: PostureFinding) = Triple(finding.access, finding.packageName, finding.componentName)
        val fresh = findings.associateBy(::key)
        val retained = previous.findings.filter { old -> old.systemApp == false &&
            !TrustedPackageWhitelist.hasProtectedNamespace(old.packageName) && old.access in unavailable &&
            (fresh[key(old)] == null || fresh[key(old)]?.state == PostureGrantState.UNKNOWN ||
                (fresh[key(old)]?.state == PostureGrantState.ENABLED && fresh[key(old)]?.systemApp == null)) }
            .map { it.copy(stale = true) }
        val replaced = retained.map(::key).toSet()
        return copy(findings = findings.filterNot { key(it) in replaced } + retained)
    }
}

data class PostureCapability(val access: PostureAccess, val packageName: String)
data class PostureChange(val capability: PostureCapability, val observedAt: Long)

/** Only identifiers for enabled access, coverage, and undelivered changes are persisted. */
data class PostureSnapshot(
    val initialized: Set<PostureAccess> = emptySet(),
    val grants: Set<PostureCapability> = emptySet(),
    val pending: Set<PostureChange> = emptySet(),
    val lastCompleteCheckAt: Long = 0
)

object PostureSnapshotComparison {
    val monitored = setOf(PostureAccess.ACCESSIBILITY, PostureAccess.DEVICE_ADMIN, PostureAccess.NOTIFICATION_LISTENER)

    /** Missing categories retain their old baseline. First successful reads initialize silently. */
    fun advance(previous: PostureSnapshot, report: DevicePostureReport): PostureSnapshot {
        val initialized = previous.initialized.toMutableSet()
        val grants = previous.grants.toMutableSet()
        val pending = previous.pending.toMutableSet()
        for (access in monitored - report.unavailable) {
            val current = report.grants(access)
            val old = grants.filter { it.access == access }.toSet()
            pending.removeAll { it.capability.access == access && it.capability !in current }
            if (access in initialized) {
                for (newGrant in current - old) {
                    if (pending.none { it.capability == newGrant }) pending += PostureChange(newGrant, report.checkedAt)
                }
            }
            grants.removeAll { it.access == access }
            grants.addAll(current)
            initialized += access
        }
        return PostureSnapshot(initialized, grants, pending,
            if ((monitored intersect report.unavailable).isEmpty()) report.checkedAt else previous.lastCompleteCheckAt)
    }
}
