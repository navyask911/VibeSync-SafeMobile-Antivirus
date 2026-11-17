#!/usr/bin/env python3
"""Static release guard for SafeMobile v1.10.5 scan, SAF, 16 KB and edge-to-edge requirements."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "gradle": "app/build.gradle.kts",
    "activity": "app/src/main/java/com/vibesync/antivirus/MainActivity.kt",
    "screen": "app/src/main/java/com/vibesync/antivirus/presentation/SafeMobileScreen.kt",
    "verifier": "app/src/main/java/com/vibesync/antivirus/core/security/SecurityVerifier.kt",
    "baseline": "app/src/main/java/com/vibesync/antivirus/core/security/LocalBaselineTrust.kt",
    "score": "app/src/main/java/com/vibesync/antivirus/core/security/DeviceSecurityScore.kt",
    "worker": "app/src/main/java/com/vibesync/antivirus/core/worker/DeepScanWorker.kt",
    "scheduler": "app/src/main/java/com/vibesync/antivirus/core/worker/DeepScanScheduler.kt",
    "service": "app/src/main/java/com/vibesync/antivirus/core/worker/ScanForegroundService.kt",
    "dao": "app/src/main/java/com/vibesync/antivirus/data/local/ThreatDao.kt",
    "repository": "app/src/main/java/com/vibesync/antivirus/data/repository/ThreatRepository.kt",
    "coordinator": "app/src/main/java/com/vibesync/antivirus/core/worker/ScanExecutionCoordinator.kt",
}
errors = []
source = {}
for key, relative in FILES.items():
    try:
        source[key] = (ROOT / relative).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"Missing {relative}: {error}")
        source[key] = ""

gradle = source["gradle"]
version_name = re.search(r'\bversionName\s*=\s*"([^"]+)"', gradle)
version_code = re.search(r"\bversionCode\s*=\s*(\d+)", gradle)
ndk = re.search(r'\bndkVersion\s*=\s*"([^"]+)"', gradle)
if not version_name or version_name.group(1) != "1.10.5":
    errors.append("Gradle versionName must be 1.10.5.")
if not version_code or version_code.group(1) != "20261158":
    errors.append("Gradle versionCode must be 20261158.")
if not ndk or tuple(int(part) for part in ndk.group(1).split(".")[:1]) < (28,):
    errors.append("Gradle must pin Android NDK r28 or higher.")
if "com.google.ai.edge.litert:litert:1.4.2" not in gradle:
    errors.append("16 KB-compatible LiteRT Interpreter runtime 1.4.2 is missing.")
if "org.tensorflow:tensorflow-lite" in gradle:
    errors.append("Legacy TensorFlow Lite AAR must not remain alongside LiteRT.")

activity = source["activity"]
on_create = activity.split("override fun onCreate", 1)[-1].split("override fun onNewIntent", 1)[0]
if "enableEdgeToEdge()" not in on_create:
    errors.append("MainActivity.onCreate must explicitly call enableEdgeToEdge().")
if "LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS" not in on_create:
    errors.append("MainActivity.onCreate must set LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS on API 30+.")
if "setStatusBarColor" in activity or "setNavigationBarColor" in activity:
    errors.append("MainActivity must not use deprecated Window status/navigation color setters.")
if "WindowInsets.safeDrawing" not in source["screen"] and "WindowInsets.systemBars" not in source["screen"]:
    errors.append("Compose screen must apply safeDrawing or systemBars insets.")

baseline = source["baseline"]
for required in (
    "Build.TAGS", "test-keys", "Settings.Global.ADB_ENABLED",
    "ro.boot.verifiedbootstate", "GoogleApiAvailability",
    "NET_CAPABILITY_VALIDATED",
):
    if required not in baseline:
        errors.append(f"Local baseline is missing required heuristic: {required}.")
if "endpoint.isBlank() || !validatedInternet" not in baseline:
    errors.append("Local fallback must apply when the remote URL is absent or internet is not validated.")
if "LOCAL_BASELINE_PASSED" not in source["verifier"] or "applyLocalBaselineFallback" not in source["verifier"]:
    errors.append("SecurityVerifier does not publish the local-baseline fallback result.")
worker = source["worker"]
if 'Log.d("ScanDebug", "Worker STARTED for: $tags")' not in worker:
    errors.append("DeepScanWorker must log its WorkManager tags when it starts.")
if 'Log.e("ScanDebug", "Worker CRASHED", error)' not in worker:
    errors.append("DeepScanWorker must log caught worker failures.")
if 'Log.d("ScanDebug", "Worker FINISHED with result: $result")' not in worker:
    errors.append("DeepScanWorker must log its terminal result.")
if "clearScanSessionStateCheckpoints()" not in worker:
    errors.append("DeepScanWorker must clear Room checkpoints before a fresh session.")
scheduler = source["scheduler"]
if ".setRequiredNetworkType(NetworkType.NOT_REQUIRED)" not in scheduler:
    errors.append("Periodic scans must explicitly use NetworkType.NOT_REQUIRED.")
if '.cancelAllWorkByTag(WORK_TAG)' not in scheduler or 'const val WORK_TAG = "ScanWorker"' not in scheduler:
    errors.append("New scans must reset stale tagged ScanWorker work.")
if ".addTag(WORK_TAG)" not in scheduler:
    errors.append("Periodic deep-scan work must carry the ScanWorker tag.")
coordinator = source["coordinator"]
if "ScanExecutionCoordinator.mutex.withLock" not in source["service"] or "ScanExecutionCoordinator.mutex.withLock" not in worker:
    errors.append("Foreground and periodic scans must share the process scan mutex.")
service = source["service"]
if "operation == OP_RESUME || operation == null" not in service:
    errors.append("Only explicit/system service redelivery may resume an interrupted scan.")
if "repo.clearScanSessionStateCheckpoints()" not in service:
    errors.append("Fresh foreground scans must clear stale Room checkpoints.")
dao = source["dao"]
if '@Query("DELETE FROM scan_session_state")' not in dao or "suspend fun clearAllSessions()" not in dao:
    errors.append("ThreatDao must expose clearAllSessions() for scan_session_state.")
repository = source["repository"]
if 'Log.d("ScanDebug", "Scanning: ${result.packageName ?: result.displayName}")' not in repository:
    errors.append("Installed-app scan loops must emit per-item ScanDebug logs.")
if 'Log.d("ScanDebug", "Scanning: ${file.displayName}")' not in repository:
    errors.append("SAF file scan loops must emit per-item ScanDebug logs.")
if "persistedUriPermissions" not in source["screen"] or "persistedReadGrants.isNotEmpty()" not in source["screen"]:
    errors.append("Deep scan must revalidate persisted SAF read grants and reprompt when absent.")

if "integrityCheckPassed" not in source["score"]:
    errors.append("Device Security Score does not consume the effective remote-or-local integrity result.")

if errors:
    print(f"Android release readiness FAILED ({len(errors)} issue(s)):")
    print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
    sys.exit(1)
print("Android release readiness passed: v1.10.5/20261158, NDK r28+, LiteRT 1.4.2, offline scan work and SAF grants.")
